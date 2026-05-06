import { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, CheckCircle, Activity, RefreshCw, HelpCircle } from 'lucide-react';

const API = 'http://localhost:8000';

const COLORS = {
  MALICIOUS: '#ef4444',
  SUSPICIOUS: '#f97316',
  SAFE: '#22c55e',
  POTENTIAL_ZERO_DAY: '#a855f7'
};

function StatusBadge({ classification }) {
  const colors = {
    MALICIOUS:          'bg-red-100 text-red-700 border border-red-300',
    SUSPICIOUS:         'bg-orange-100 text-orange-700 border border-orange-300',
    SAFE:               'bg-green-100 text-green-700 border border-green-300',
    POTENTIAL_ZERO_DAY: 'bg-purple-100 text-purple-700 border border-purple-300'
  };
  const icons = {
    MALICIOUS:          <AlertTriangle size={14} />,
    SUSPICIOUS:         <AlertTriangle size={14} />,
    SAFE:               <CheckCircle size={14} />,
    POTENTIAL_ZERO_DAY: <HelpCircle size={14} />
  };
  const labels = {
    POTENTIAL_ZERO_DAY: 'Zero-Day?'
  };
  return (
    <span className={`flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold ${colors[classification]}`}>
      {icons[classification]} {labels[classification] || classification}
    </span>
  );
}

function StatCard({ title, value, icon, color }) {
  return (
    <div className={`bg-white rounded-xl p-5 shadow-sm border-l-4 ${color}`}>
      <div className="flex justify-between items-start">
        <div>
          <p className="text-sm text-gray-500">{title}</p>
          <p className="text-3xl font-bold mt-1">{value}</p>
        </div>
        <div className="text-gray-400">{icon}</div>
      </div>
    </div>
  );
}

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(null);

  const fetchAlerts = async () => {
    try {
      const res = await axios.get(`${API}/api/alerts`);
      setAlerts(res.data.alerts ?? []);
      setLastUpdate(new Date().toLocaleTimeString());
    } catch (e) {
      console.error('API Error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const stats = {
    total: alerts.length,
    malicious: alerts.filter(a => a.classification === 'MALICIOUS').length,
    suspicious: alerts.filter(a => a.classification === 'SUSPICIOUS').length,
    safe: alerts.filter(a => a.classification === 'SAFE').length,
  };

  const pieData = [
    { name: 'Malicious', value: stats.malicious },
    { name: 'Suspicious', value: stats.suspicious },
    { name: 'Safe', value: stats.safe },
  ].filter(d => d.value > 0);

  const barData = alerts.slice(0, 10).reverse().map(a => ({
    name: a.process_name,
    score: parseFloat((a.final_score * 100).toFixed(1))
  }));

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-gray-900 text-white px-8 py-4 flex justify-between items-center shadow">
        <div className="flex items-center gap-3">
          <Shield size={28} className="text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">Quantum EDR</h1>
            <p className="text-xs text-gray-400">Endpoint Detection & Response</p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-sm text-gray-400">
          <Activity size={16} className="text-green-400" />
          <span>Live</span>
          {lastUpdate && <span>· Updated {lastUpdate}</span>}
          <button onClick={fetchAlerts} className="ml-2 p-1 hover:text-white transition">
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <StatCard title="Total Alerts" value={stats.total} icon={<Shield size={24}/>} color="border-blue-500" />
          <StatCard title="Malicious" value={stats.malicious} icon={<AlertTriangle size={24}/>} color="border-red-500" />
          <StatCard title="Suspicious" value={stats.suspicious} icon={<AlertTriangle size={24}/>} color="border-orange-500" />
          <StatCard title="Safe" value={stats.safe} icon={<CheckCircle size={24}/>} color="border-green-500" />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-3 gap-6 mb-8">
          <div className="col-span-2 bg-white rounded-xl p-5 shadow-sm">
            <h2 className="font-semibold text-gray-700 mb-4">Risk Scores</h2>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={barData}>
                <XAxis dataKey="name" tick={{fontSize: 11}} />
                <YAxis domain={[0, 100]} />
                <Tooltip formatter={(v) => `${v}%`} />
                <Bar dataKey="score" fill="#3b82f6" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="bg-white rounded-xl p-5 shadow-sm">
            <h2 className="font-semibold text-gray-700 mb-4">Distribution</h2>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={70} dataKey="value" label={({name, percent}) => `${name} ${(percent*100).toFixed(0)}%`}>
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={Object.values(COLORS)[i]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="bg-white rounded-xl shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b flex justify-between items-center">
            <h2 className="font-semibold text-gray-700">Recent Alerts</h2>
            <span className="text-sm text-gray-400">{alerts.length} total</span>
          </div>
          {loading ? (
            <div className="p-8 text-center text-gray-400">Loading...</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-gray-500 uppercase text-xs">
                <tr>
                  <th className="px-6 py-3 text-left">Process</th>
                  <th className="px-6 py-3 text-left">PID</th>
                  <th className="px-6 py-3 text-left">Classification</th>
                  <th className="px-6 py-3 text-left">Score</th>
                  <th className="px-6 py-3 text-left">Mode</th>
                  <th className="px-6 py-3 text-left">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {alerts.map(alert => (
                  <tr key={alert.id} className="hover:bg-gray-50 transition">
                    <td className="px-6 py-3 font-mono font-medium">{alert.process_name}</td>
                    <td className="px-6 py-3 text-gray-500">{alert.pid}</td>
                    <td className="px-6 py-3"><StatusBadge classification={alert.classification} /></td>
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-24 bg-gray-200 rounded-full h-2">
                          <div className="h-2 rounded-full" style={{
                            width: `${alert.final_score * 100}%`,
                            backgroundColor: COLORS[alert.classification]
                          }}/>
                        </div>
                        <span className="text-gray-600">{(alert.final_score * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-gray-500">{alert.mode}</td>
                    <td className="px-6 py-3 text-gray-500">{new Date(alert.timestamp).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}