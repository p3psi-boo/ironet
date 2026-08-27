//! Small, bounded JSON-lines codec shared by local control and enrollment.

use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) async fn read<T, R>(reader: &mut R, maximum: usize) -> Result<T>
where
    T: DeserializeOwned,
    R: AsyncBufRead + Unpin,
{
    let line = read_bounded_line(reader, maximum).await?;
    ensure!(!line.is_empty(), "empty JSON-line message");
    serde_json::from_slice(&line).context("invalid JSON-line message")
}

pub(crate) async fn write<T, W>(writer: &mut W, value: &T, maximum: usize) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let mut encoded = serde_json::to_vec(value).context("encoding JSON-line message")?;
    ensure!(
        encoded.len() <= maximum,
        "JSON-line message exceeds {maximum} bytes"
    );
    encoded.push(b'\n');
    writer
        .write_all(&encoded)
        .await
        .context("writing JSON-line message")
}

pub(crate) async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let (take, finished) = {
            let available = reader
                .fill_buf()
                .await
                .context("reading JSON-line message")?;
            if available.is_empty() {
                return Ok(line);
            }
            let take = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            ensure!(
                line.len() + take <= maximum,
                "JSON-line message exceeds {maximum} bytes"
            );
            line.extend_from_slice(&available[..take]);
            (take, available[take - 1] == b'\n')
        };
        reader.consume(take);
        if finished {
            line.pop();
            return Ok(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn bounded_reader_rejects_an_oversized_unterminated_frame() {
        let bytes = vec![b'x'; 9];
        let mut reader = BufReader::new(bytes.as_slice());
        let error = read_bounded_line(&mut reader, 8).await.unwrap_err();
        assert!(error.to_string().contains("exceeds 8 bytes"));
    }
}
