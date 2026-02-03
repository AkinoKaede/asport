use std::sync::Arc;
use parking_lot::Mutex;

/// A thread-safe buffer pool to avoid frequent allocations
pub struct BufferPool {
    buffers: Arc<Mutex<Vec<Vec<u8>>>>,
    max_pool_size: usize,
    buffer_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(buffer_size: usize, max_pool_size: usize) -> Self {
        Self {
            buffers: Arc::new(Mutex::new(Vec::new())),
            max_pool_size,
            buffer_size,
        }
    }

    /// Get a buffer from the pool or create a new one
    pub fn get(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock();
        if let Some(mut buffer) = buffers.pop() {
            buffer.clear();
            if buffer.capacity() < self.buffer_size {
                buffer.reserve(self.buffer_size - buffer.capacity());
            }
            buffer
        } else {
            Vec::with_capacity(self.buffer_size)
        }
    }

    /// Return a buffer to the pool
    pub fn put(&self, mut buffer: Vec<u8>) {
        let mut buffers = self.buffers.lock();
        if buffers.len() < self.max_pool_size && buffer.capacity() >= self.buffer_size / 2 {
            buffer.clear();
            buffers.push(buffer);
        }
        // If pool is full or buffer is too small, just drop it
    }
}

impl Clone for BufferPool {
    fn clone(&self) -> Self {
        Self {
            buffers: self.buffers.clone(),
            max_pool_size: self.max_pool_size,
            buffer_size: self.buffer_size,
        }
    }
}
