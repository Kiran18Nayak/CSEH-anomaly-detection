import React, { useState } from "react";

// Function to parse a PCAP file and extract packet timestamps
const parsePcapFile = async (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const arrayBuffer = reader.result;
        const view = new DataView(arrayBuffer);

        const packets = [];
        let offset = 24; // Initial offset after the global header (24 bytes)

        while (offset < view.byteLength) {
          const tsSec = view.getUint32(offset, true); // Timestamp seconds
          const tsUsec = view.getUint32(offset + 4, true); // Timestamp microseconds
          const inclLen = view.getUint32(offset + 8, true); // Number of octets of packet saved in file
          // Skipping the original length (offset + 12) as we just need inclLen to jump to the next packet

          const timestamp = tsSec + tsUsec / 1e6;
          packets.push({ timestamp });

          offset += 16 + inclLen; // Move to the next packet header
        }

        console.log("Parsed packets:", packets);
        resolve(packets);
      } catch (error) {
        console.error("Error during file processing:", error);
        reject(error);
      }
    };

    reader.onerror = (error) => {
      console.error("File reading error:", error);
      reject(error);
    };

    reader.readAsArrayBuffer(file);
  });
};

// Function to detect anomalies based on packet timestamps
const detectAnomalies = (packets) => {
  const timeIntervals = packets.map((packet) => packet.timestamp);
  console.log("Packet timestamps:", timeIntervals);
  const differences = timeIntervals
    .slice(1)
    .map((time, index) => time - timeIntervals[index]);
  console.log("Time differences:", differences);

  // Detect if there is a sudden rise in packet frequency
  for (let i = 1; i < differences.length; i++) {
    if (differences[i - 1] > 0.05 && differences[i] < 0.02) {
      return true; // Anomaly detected
    }
  }
  return false; // No anomaly detected
};

const AnomalyDetector = () => {
  const [anomalyDetected, setAnomalyDetected] = useState(false);
  const [noAnomalyDetected, setNoAnomalyDetected] = useState(false);

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    console.log("File selected:", file);
    try {
      const packets = await parsePcapFile(file);
      console.log("Packets parsed from file:", packets);

      const isAnomalyDetected = detectAnomalies(packets);

      setAnomalyDetected(isAnomalyDetected);
      setNoAnomalyDetected(!isAnomalyDetected);
    } catch (error) {
      console.error("Error processing the PCAP file:", error);
    }
  };

  return (
    <div>
      <h1>Wireshark Anomaly Detector</h1>
      <input type="file" accept=".pcap" onChange={handleFileUpload} />
      {anomalyDetected && (
        <div className="alert">Anomaly detected! Take action.</div>
      )}
      {noAnomalyDetected && (
        <div className="no-alert">No anomaly detected.</div>
      )}
    </div>
  );
};

export default AnomalyDetector;