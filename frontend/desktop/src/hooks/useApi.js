import { useState, useEffect } from 'react';
import { getHealth } from '../utils/api';

export function useApi() {
  const [health, setHealth] = useState(null);
  const [isOnline, setIsOnline] = useState(false);

  useEffect(() => {
    let interval;
    
    const checkHealth = async () => {
      try {
        const data = await getHealth();
        setHealth(data);
        setIsOnline(data.status === 'healthy');
      } catch (err) {
        setHealth(null);
        setIsOnline(false);
      }
    };

    checkHealth();
    interval = setInterval(checkHealth, 30000); // Check every 30s

    return () => clearInterval(interval);
  }, []);

  return { health, isOnline };
}
