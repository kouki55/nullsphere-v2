import { useEffect, useRef, useCallback, useState, createContext, useContext, ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';

interface UseSocketOptions {
  autoConnect?: boolean;
  reconnection?: boolean;
  reconnectionDelay?: number;
  reconnectionDelayMax?: number;
  reconnectionAttempts?: number;
}

const defaultOptions: UseSocketOptions = {
  autoConnect: true,
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  reconnectionAttempts: 5,
};

export function useSocket(options: UseSocketOptions = {}) {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const opts = { ...defaultOptions, ...options };

  useEffect(() => {
    const socket = io(window.location.origin, {
      autoConnect: opts.autoConnect,
      reconnection: opts.reconnection,
      reconnectionDelay: opts.reconnectionDelay,
      reconnectionDelayMax: opts.reconnectionDelayMax,
      reconnectionAttempts: opts.reconnectionAttempts,
      transports: ['websocket', 'polling'],
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      console.log('[useSocket] Connected:', socket.id);
      setIsConnected(true);
      setError(null);
    });

    socket.on('disconnect', () => {
      console.log('[useSocket] Disconnected');
      setIsConnected(false);
    });

    socket.on('error', (err: any) => {
      console.error('[useSocket] Error:', err);
      setError(err instanceof Error ? err : new Error(String(err)));
    });

    return () => {
      if (socket) {
        socket.disconnect();
      }
    };
  }, [opts.autoConnect, opts.reconnection, opts.reconnectionDelay, opts.reconnectionDelayMax, opts.reconnectionAttempts]);

  const emit = useCallback(
    (event: string, data?: any, callback?: (response: any) => void) => {
      if (socketRef.current?.connected) {
        socketRef.current.emit(event, data, callback);
      } else {
        console.warn('[useSocket] Socket not connected, cannot emit event:', event);
      }
    },
    []
  );

  const on = useCallback((event: string, handler: (...args: any[]) => void) => {
    if (socketRef.current) {
      socketRef.current.on(event, handler);
    }

    return () => {
      if (socketRef.current) {
        socketRef.current.off(event, handler);
      }
    };
  }, []);

  const off = useCallback((event: string, handler?: (...args: any[]) => void) => {
    if (socketRef.current) {
      if (handler) {
        socketRef.current.off(event, handler);
      } else {
        socketRef.current.off(event);
      }
    }
  }, []);

  const once = useCallback((event: string, handler: (...args: any[]) => void) => {
    if (socketRef.current) {
      socketRef.current.once(event, handler);
    }
  }, []);

  return {
    socket: socketRef.current,
    isConnected,
    error,
    emit,
    on,
    off,
    once,
  };
}

interface SocketContextType {
  socket: Socket | null;
  isConnected: boolean;
  error: Error | null;
  emit: (event: string, data?: any, callback?: (response: any) => void) => void;
  on: (event: string, handler: (...args: any[]) => void) => () => void;
  off: (event: string, handler?: (...args: any[]) => void) => void;
  once: (event: string, handler: (...args: any[]) => void) => void;
}

const SocketContext = createContext<SocketContextType | undefined>(undefined);

export function SocketProvider({ children }: { children: ReactNode }) {
  const socketMethods = useSocket();

  return (
    <SocketContext.Provider value={socketMethods}>
      {children}
    </SocketContext.Provider>
  );
}

export function useSocketContext() {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocketContext must be used within SocketProvider');
  }
  return context;
}
