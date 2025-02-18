import { useEffect, useRef } from 'react';
import {
  PixelRatio,
  Platform,
  UIManager,
  findNodeHandle,
  requireNativeComponent,
} from 'react-native';

const NativeSecureView = requireNativeComponent('SecureView');

const createFragment = (viewId: number | null) => {
  UIManager.dispatchViewManagerCommand(
    viewId,
    UIManager.SecureView.Commands.create.toString(),
    [viewId]
  );
};

export const SecureView = () => {
  const ref = useRef(null);

  useEffect(() => {
    const viewId = findNodeHandle(ref.current);
    createFragment(viewId);
  }, []);

  if (Platform.OS === 'ios') return NativeSecureView;

  return (
    <NativeSecureView
      style={{
        // converts dpi to px, provide desired height
        height: PixelRatio.getPixelSizeForLayoutSize(200),
        // converts dpi to px, provide desired width
        width: PixelRatio.getPixelSizeForLayoutSize(200),
      }}
      ref={ref}
    />
  );
};
