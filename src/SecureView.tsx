import { useEffect, useRef } from 'react';
import {
  Platform,
  UIManager,
  findNodeHandle,
  requireNativeComponent,
} from 'react-native';

const NativeComponent = requireNativeComponent('SecureView');

const createFragment = (viewId: number | null) => {
  if (!UIManager.getViewManagerConfig) return;

  const viewManagerConfig = UIManager.getViewManagerConfig('SecureView');

  if (viewManagerConfig.Commands.create) {
    UIManager.dispatchViewManagerCommand(
      viewId,
      viewManagerConfig.Commands.create,
      [viewId]
    );
  }
};

export const SecureView = (props: any) => {
  const ref = useRef(null);

  useEffect(() => {
    const viewId = findNodeHandle(ref.current);
    if (Platform.OS === 'android') createFragment(viewId);
  }, []);

  return <NativeComponent {...props} ref={ref} />;
};
