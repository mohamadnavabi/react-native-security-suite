package com.securitysuite;

import org.junit.Test;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

import static org.junit.Assert.assertEquals;

public class SslpinningNetworkErrorTest {
  @Test
  public void unknownHost() {
    assertEquals("UNKNOWN_HOST", Sslpinning.networkError(new UnknownHostException("api.example.com")));
  }

  @Test
  public void peerUnverified() {
    assertEquals("SSL_PEER_UNVERIFIED",
        Sslpinning.networkError(new SSLPeerUnverifiedException("Certificate pinning failure!")));
  }

  @Test
  public void handshake() {
    assertEquals("SSL_HANDSHAKE",
        Sslpinning.networkError(new SSLHandshakeException("Trust anchor for certification path not found.")));
  }

  @Test
  public void timeout() {
    assertEquals("TIMEOUT", Sslpinning.networkError(new SocketTimeoutException("timeout")));
  }

  @Test
  public void otherIoFailures() {
    assertEquals("NETWORK", Sslpinning.networkError(new ConnectException("Failed to connect")));
    assertEquals("NETWORK", Sslpinning.networkError(new IOException("unexpected end of stream")));
  }
}
