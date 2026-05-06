import axios from 'axios';

// Get base URL from environment or fallback to localhost
const API_BASE_URL = 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getHealth = async () => {
  const response = await axios.get('http://localhost:8000/health');
  return response.data;
};

export const getAlerts = async (skip = 0, limit = 50, classification = null, status = null) => {
  const params = { skip, limit };
  if (classification) params.classification = classification;
  if (status) params.status = status;
  
  const response = await api.get('/alerts', { params });
  return response.data;
};

export const getAlert = async (id) => {
  const response = await api.get(`/alerts/${id}`);
  return response.data;
};

export const updateAlertStatus = async (id, status) => {
  const response = await api.patch(`/alerts/${id}`, { status });
  return response.data;
};

export const analyzeAlert = async (id) => {
  const response = await api.post(`/analyze/${id}`);
  return response.data;
};

export const getStats = async () => {
  const response = await api.get('/stats');
  return response.data;
};

export const getReport = async (id) => {
  const response = await api.get(`/report/${id}`);
  return response.data;
};

export default api;
