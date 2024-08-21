use std::sync::atomic::Ordering;

use bytes::Bytes;
use quinn::{RecvStream, SendStream, VarInt};
use register_count::Register;
use tokio::time;

use asport_quinn::Task;

use crate::error::Error;

use super::Connection;

impl Connection {
    pub async fn handle_uni_stream(self, recv: RecvStream, _reg: Register) {
        log::debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming unidirectional stream",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

        if self.remote_uni_stream_cnt.count() as u32 == max {
            self.max_concurrent_uni_streams
                .store(max * 2, Ordering::Relaxed);

            self.inner
                .set_max_concurrent_uni_streams(VarInt::from(max * 2));
        }

        let pre_process = async {
            let task = time::timeout(
                self.task_negotiation_timeout,
                self.model.accept_uni_stream(recv),
            )
                .await
                .map_err(|_| Error::TaskNegotiationTimeout)??;


            if let Task::ClientHello(client_hello) = &task {
                self.handshake(client_hello).await?;
            };

            tokio::select! {
                () = self.auth.clone() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::ClientHello(client_hello)) => self.handle_client_hello(client_hello).await,
            Ok(Task::Packet(pkt)) => self.handle_packet(pkt).await,
            Ok(_) => unreachable!(),
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming unidirectional stream error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
    }

    pub async fn handle_bi_stream(self, (send, recv): (SendStream, RecvStream), _reg: Register) {
        log::debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming bidirectional stream",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

        if self.remote_bi_stream_cnt.count() as u32 == max {
            self.max_concurrent_bi_streams
                .store(max * 2, Ordering::Relaxed);

            self.inner
                .set_max_concurrent_bi_streams(VarInt::from(max * 2));
        }

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

        match pre_process.await {
            Ok(_) => unreachable!(),
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming bidirectional stream error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
    }


    pub async fn handle_datagram(self, dg: Bytes) {
        log::debug!(
            "[{id:#010x}] [{addr}] [{user}] incoming datagram",
            id = self.id(),
            addr = self.inner.remote_address(),
            user = self.auth,
        );

        let pre_process = async {
            let task = self.model.accept_datagram(dg)?;

            tokio::select! {
                () = self.auth.clone() => {}
                err = self.inner.closed() => return Err(Error::from(err)),
            };

            Ok(task)
        };

        match pre_process.await {
            Ok(Task::Heartbeat) => self.handle_heartbeat().await,
            Ok(Task::Packet(pkt)) => self.handle_packet(pkt).await,
            Ok(_) => unreachable!(),
            Err(err) => {
                log::warn!(
                    "[{id:#010x}] [{addr}] [{user}] handling incoming datagram error: {err}",
                    id = self.id(),
                    addr = self.inner.remote_address(),
                    user = self.auth,
                );
                self.close();
            }
        }
    }
}