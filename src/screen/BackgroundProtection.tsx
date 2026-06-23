import React, { useEffect, useRef, useState } from 'react';
import { AppState, type AppStateStatus, StyleSheet, View } from 'react-native';
import { getNativeModule } from '../native/bridge';

export interface BackgroundProtectionOptions {
  /** Color of the privacy overlay shown when the app is inactive/backgrounded. Default: '#000000' */
  backgroundColor?: string;
  /** Opacity of the overlay. Default: 1 */
  opacity?: number;
  /**
   * Also call the native `screenSetWindowSecure` API to set FLAG_SECURE (Android)
   * or a system-level blur (iOS). Default: false
   */
  useNativeWindowSecure?: boolean;
}

/**
 * Wrap your root component with this to display a privacy overlay whenever
 * the app is inactive or backgrounded, preventing the OS app-switcher screenshot
 * from capturing sensitive content.
 */
export function BackgroundProtection({
  backgroundColor = '#000000',
  opacity = 1,
  useNativeWindowSecure = false,
  children,
}: BackgroundProtectionOptions & {
  children?: React.ReactNode;
}): React.ReactElement {
  const [hidden, setHidden] = useState(false);

  useEffect(() => {
    if (useNativeWindowSecure) {
      getNativeModule()
        .screenSetWindowSecure(true)
        .catch(() => undefined);
    }

    const sub = AppState.addEventListener('change', (next: AppStateStatus) => {
      setHidden(next !== 'active');
    });

    return () => {
      sub.remove();
      if (useNativeWindowSecure) {
        getNativeModule()
          .screenSetWindowSecure(false)
          .catch(() => undefined);
      }
    };
  }, [useNativeWindowSecure]);

  return (
    <>
      {children}
      {hidden && (
        <View
          style={[
            StyleSheet.absoluteFillObject,
            { backgroundColor, opacity, zIndex: 999999 },
          ]}
        />
      )}
    </>
  ) as React.ReactElement;
}

/**
 * React hook that returns `true` while the app is inactive or in the background.
 * Use it to conditionally hide sensitive UI elements.
 */
export function useBackgroundProtection(
  options: BackgroundProtectionOptions = {}
): boolean {
  const [isBackground, setIsBackground] = useState<boolean>(
    AppState.currentState !== 'active'
  );
  const nativeSet = useRef(false);

  useEffect(() => {
    if (options.useNativeWindowSecure && !nativeSet.current) {
      nativeSet.current = true;
      getNativeModule()
        .screenSetWindowSecure(true)
        .catch(() => undefined);
    }

    const sub = AppState.addEventListener('change', (next: AppStateStatus) => {
      setIsBackground(next !== 'active');
    });

    return () => {
      sub.remove();
      if (nativeSet.current) {
        nativeSet.current = false;
        getNativeModule()
          .screenSetWindowSecure(false)
          .catch(() => undefined);
      }
    };
  }, [options.useNativeWindowSecure]);

  return isBackground;
}

export const ScreenSecurity = {
  /**
   * Enable or disable the native window-level security flag.
   * On Android: sets/clears `FLAG_SECURE` on the Activity window.
   * On iOS: adds/removes a UIVisualEffectView over the key window.
   */
  setWindowSecure(enabled: boolean): Promise<void> {
    return getNativeModule()
      .screenSetWindowSecure(enabled)
      .catch(() => undefined);
  },
};
