import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import PacketWindow from './pages/PacketWindow';
import Analyze from './pages/Analyze';
import Configurations from './pages/Configurations';
// import Settings from './pages/Settings';

export default function App() {
  return (
    <Router>
      <div className="app">
        {/* Header Navigation */}
        <header>
          <Link to="/" className="nav-item">Packet Window</Link>
          <Link to="/analyze" className="nav-item">Analyze</Link>
          <Link to="/configurations" className="nav-item">Configurations</Link>
        </header>

        {/* Main Content */}
        <div className="page-container">
          <Routes>
            <Route path="/" element={<PacketWindow />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/configurations" element={<Configurations />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}