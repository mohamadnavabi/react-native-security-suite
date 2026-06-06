package com.securitysuite;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecureStorageNativeTest {
  @Test
  public void secureStorageException_includesOperationAndFailureMessage() {
    Exception wrapped =
        invokeSecureStorageException(
            "setItem", new IllegalArgumentException("Storage key is required"));

    assertTrue(wrapped.getMessage().startsWith("Secure storage operation failed"));
    assertTrue(wrapped.getMessage().contains("(setItem)"));
    assertTrue(wrapped.getMessage().contains("Storage key is required"));
  }

  @Test
  public void secureStorageException_usesExceptionTypeWhenMessageMissing() {
    Exception wrapped = invokeSecureStorageException("getItem", new RuntimeException());

    assertEquals(
        "Secure storage operation failed (getItem): RuntimeException",
        wrapped.getMessage());
  }

  private static Exception invokeSecureStorageException(String operation, Exception cause)
      throws Exception {
    var method =
        SecureStorageNative.class.getDeclaredMethod(
            "secureStorageException", String.class, Exception.class);
    method.setAccessible(true);
    return (Exception) method.invoke(null, operation, cause);
  }
}
