import { SecurityError, SecurityErrorCode } from '../errors';

export interface ClipboardGuardOptions {
  /** Automatically clear the clipboard after this many milliseconds. */
  clearAfterMs?: number;
}

type ClipboardAPI = {
  getString(): Promise<string>;
  setString(text: string): void;
};

function resolveClipboard(): ClipboardAPI {
  try {
    return require('@react-native-clipboard/clipboard').default as ClipboardAPI; // eslint-disable-line @typescript-eslint/no-require-imports
  } catch {
    try {
      const { Clipboard } = require('react-native'); // eslint-disable-line @typescript-eslint/no-require-imports
      if (Clipboard && typeof Clipboard.setString === 'function') {
        return Clipboard as ClipboardAPI;
      }
    } catch {
      // ignore
    }
  }
  throw new SecurityError(
    SecurityErrorCode.CLIPBOARD_UNAVAILABLE,
    'No clipboard provider found. Install @react-native-clipboard/clipboard.'
  );
}

let _autoClearTimer: ReturnType<typeof setTimeout> | null = null;

function cancelAutoClear(): void {
  if (_autoClearTimer !== null) {
    clearTimeout(_autoClearTimer);
    _autoClearTimer = null;
  }
}

export const ClipboardGuard = {
  /**
   * Write text to the clipboard. Optionally auto-clear after `clearAfterMs` ms.
   * Cancels any previously scheduled auto-clear before setting the new one.
   */
  copy(text: string, options: ClipboardGuardOptions = {}): void {
    cancelAutoClear();
    const clipboard = resolveClipboard();
    clipboard.setString(text);
    if (options.clearAfterMs != null && options.clearAfterMs > 0) {
      _autoClearTimer = setTimeout(() => {
        clipboard.setString('');
        _autoClearTimer = null;
      }, options.clearAfterMs);
    }
  },

  /** Immediately clear the clipboard and cancel any pending auto-clear. */
  clear(): void {
    cancelAutoClear();
    resolveClipboard().setString('');
  },

  /** Cancel a pending auto-clear without wiping the clipboard. */
  cancelAutoClear(): void {
    cancelAutoClear();
  },

  /** Read the current clipboard contents. */
  read(): Promise<string> {
    return resolveClipboard().getString();
  },
};
