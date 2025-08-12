use std::sync::atomic::Ordering;

use bytes::Bytes;
use quinn::{RecvStream, SendStream, VarInt};
use register_count::Register;
use tokio::time;

use asport_quinn::Task;

use crate::{
    error::Error,
    utils::{Network, UdpForwardMode},
};

use super::Connection;

impl Connection {
    pub async fn accept_uni_stream(&self) -> Result<(RecvStream, Register), Error> {
        let max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

        if self.remote_uni_stream_cnt.count() as u32 == max {
            self.max_concurrent_uni_streams
                .store(max * 2, Ordering::Relaxed);

            self.inner
                .set_max_concurrent_uni_streams(VarInt::from(max * 2));
        }

        let recv = self.inner.accept_uni().await?;
        let reg = self.remote_uni_stream_cnt.reg();
        Ok((recv, reg))
    }

    pub async fn accept_bi_stream(&self) -> Result<((SendStream, RecvStream), Register), Error> {
        let max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

        if self.remote_bi_stream_cnt.count() as u32 == max {
            self.max_concurrent_bi_streams
                .store(max * 2, Ordering::Relaxed);

            self.inner
                .set_max_concurrent_bi_streams(VarInt::from(max * 2));
        }

        let stream = self.inner.accept_bi().await?;
        let reg = self.remote_bi_stream_cnt.reg();
        Ok((stream, reg))
    }

    pub async fn accept_datagram(&self) -> Result<Bytes, Error> {
        Ok(self.inner.read_datagram().await?)
    }

    pub async fn handle_uni_stream(self, recv: RecvStream, _reg: Register) {
        let pre_process = async {
            let task = time::timeout(
                self.task_negotiation_timeout,
                self.model.accept_uni_stream(recv),
            )
            .await
            .map_err(|_| Error::TaskNegotiationTimeout)??;

            if let Task::ServerHello(server_hello) = &task {
                self.handshake(server_hello).await?;
            }

            tokio::select! {
                () = self.auth.clone() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            Ok(task)
        };

        let res = match pre_process.await {
            Ok(Task::ServerHello(server_hello)) => Ok(self.handle_server_hello(server_hello).await),
            Ok(Task::Packet(pkt)) => {
                if self.network.udp() {
                    match self.udp_forward_mode {
                        UdpForwardMode::Quic => {
                            self.handle_packet(pkt).await;
                            Ok(())
                        }
                        UdpForwardMode::Native => Err(Error::WrongPacketSource),
                    }
                } else {
                    Err(Error::NetworkDenied(Network::Udp))
                }
            }
            Ok(Task::Dissociate(assoc_id)) => Ok(self.handle_dissociate(assoc_id).await),
            Ok(_) => unreachable!(),
            Err(err) => Err(err),
        };

        if let Err(err) = res {
            log::warn!("incoming unidirectional stream error: {err}");
        }
    }

    pub async fn handle_bi_stream(self, (send, recv): (SendStream, RecvStream), _reg: Register) {
        let pre_process = async {
            let task = time::timeout(
                self.task_negotiation_timeout,
                self.model.accept_bi_stream(send, recv),
            )
            .await
            .map_err(|_| Error::TaskNegotiationTimeout)??;

            tokio::select! {
                () = self.auth.clone() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            Ok(task)
        };

        let res = match pre_process.await {
            Ok(Task::Connect(connect)) => {
                if self.network.tcp() {
                    self.handle_connect(connect).await;
                    Ok(())
                } else {
                    Err(Error::NetworkDenied(Network::Tcp))
                }
            }
            Ok(_) => unreachable!(),
            Err(err) => Err(err),
        };

        if let Err(err) = res {
            log::warn!("incoming bidirectional stream error: {err}");
        }
    }

    pub async fn handle_datagram(self, dg: Bytes) {
        log::debug!("incoming datagram");
        let res = match self.model.accept_datagram(dg) {
            Err(err) => Err::<(), Error>(Error::Model(err)),
            Ok(Task::Packet(pkt)) => {
                if self.network.udp() {
                    match self.udp_forward_mode {
                        UdpForwardMode::Native => {
                            self.handle_packet(pkt).await;
                            Ok(())
                        }
                        UdpForwardMode::Quic => Err(Error::WrongPacketSource),
                    }
                } else {
                    Err(Error::NetworkDenied(Network::Udp))
                }
            }
            _ => unreachable!(),
        };

        if let Err(err) = res {
            log::warn!("incoming datagram error: {err}");
        }
    }
}
