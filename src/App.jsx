import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import EditUser from "./components/EditUser.jsx";
import Navbar from "./components/NavBar.jsx";
import Login from "./components/Login.jsx";
import Dashboard from "./components/DashBoard.jsx";
import Register from "./components/Register.jsx";
import LandingPage from "./components/landingpage.jsx";
import AddCourse from "./components/AddCource.jsx";
import EditKursus from "./components/EditKursus.jsx";
import DashboardUser from "./components/dashboarduser.jsx";
import EditIkutKursus from "./components/Editikutkursus.jsx";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Landing page untuk user yang belum login */}
        <Route path="/" element={<LandingPage />} />

        {/* Login */}
        <Route path="/login" element={<Login />} />

        {/* Register */}
        <Route path="/register" element={<Register />} />

        {/* Dashboard + Navbar, hanya untuk user yang sudah login */}
        <Route
          path="/dashboard"
          element={
            <>
              <Navbar />
              <Dashboard />
            </>
          }
        />
        <Route
          path="/add-course"
          element={
            <>
              <Navbar />
              <AddCourse />
            </>
          }
        />

           <Route
          path="/editikutkursus/:id"
          element={
            <>
              <Navbar />
              <EditIkutKursus />
            </>
          }
        />

 <Route
          path="/dashboarduser"
          element={
            <>
              <Navbar />
              <DashboardUser />
            </>
          }
        />

          <Route
  path="/edit-kursus/:id"
  element={
    <>
      <Navbar />
      <EditKursus />
    </>
  }
/>
          
        {/* Edit user */}
        <Route
          path="/edit/:id"
          element={
            <>
              <Navbar />
              <EditUser />
            </>
          }
        />

        {/* Redirect kalau path tidak ditemukan */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
