use crate::PcapData;
use netgauze_flow_pkt::FlowInfo;
use serde::Serialize;
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf};
use tokio::{fs::File as AsyncFile, io::AsyncWriteExt, io::BufWriter};

#[derive(Debug, Serialize)]
struct SerializableFlowInfo {
    info: FlowInfo,
    source_address: SocketAddr,
}

pub async fn serialize_data_to_jsonl(
    rx: async_channel::Receiver<Arc<PcapData>>,
    output_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let output_file = AsyncFile::create(output_path.as_path()).await?;
    let mut writer = BufWriter::new(output_file);

    while let Ok(pcap_data_arc) = rx.recv().await {
        match pcap_data_arc.as_ref() {
            PcapData::Flow(flow_request) => {
                let (source_address, flow_info) = flow_request;
                let serializable_flow = SerializableFlowInfo {
                    info: flow_info.clone(),
                    source_address: *source_address,
                };
                let json_string = serde_json::to_string(&serializable_flow)?;
                writer.write_all(json_string.as_bytes()).await?;
                writer.write_all(b"\n").await?; // Add a newline to separate JSON objects
            }
            PcapData::Bmp(bmp_message) => {
                let json_string = serde_json::to_string(&bmp_message)?;
                writer.write_all(json_string.as_bytes()).await?;
                writer.write_all(b"\n").await?; // Add a newline to separate JSON objects
            }
        }
    }

    writer.flush().await?;
    println!("Successfully wrote flows to {:?}", output_path);
    Ok(())
}
