import { useState, useEffect, useCallback } from 'react';
import { getAlerts, getStats } from '../utils/api';

export function useAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [alertsData, statsData] = await Promise.all([
        getAlerts(),
        getStats()
      ]);
      setAlerts(alertsData.alerts);
      setStats(statsData);
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Method to manually append a new alert (e.g. from WebSocket)
  const addAlert = useCallback((newAlert) => {
    setAlerts((prev) => [newAlert, ...prev].slice(0, 50));
  }, []);

  return { alerts, stats, loading, error, refresh: fetchData, addAlert };
}
