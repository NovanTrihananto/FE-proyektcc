import React, { useState, useEffect, useCallback } from "react";
import { useNavigate, Link } from "react-router-dom";
import useAxiosToken from "../hooks/useAxiosToken";
import { BASE_URL } from "../utils";

const Dashboard = () => {
  const { axiosJWT, token, name, role} = useAxiosToken();
  const [users, setUsers] = useState([]);
  const [courses, setCourses] = useState([]);
   const [ikutKursus, setIkutKursus] = useState([]);
  const [loadingIkutKursus, setLoadingIkutKursus] = useState(false);
  const [errorIkutKursus, setErrorIkutKursus] = useState("");
  const navigate = useNavigate();
  

  useEffect(() => {
    if (role && role !== "admin") {
      navigate("/dashboarduser"); // Ganti dengan halaman yang sesuai
    }
  }, [role, navigate]);

  const getUsers = useCallback(async () => {
    try {
      const response = await axiosJWT.get(`${BASE_URL}/users`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUsers(response.data.data);
    } catch (error) {
      console.log(error);
    }
  }, [axiosJWT, token]);

  const getCourses = useCallback(async () => {
    try {
      const response = await axiosJWT.get(`${BASE_URL}/courses`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setCourses(response.data || []);
    } catch (error) {
      console.log(error);
    }
  }, [axiosJWT, token]);

  const getIkutKursus = useCallback(async () => {
  try {
    setLoadingIkutKursus(true);
    const res = await axiosJWT.get(`${BASE_URL}/ikutkursus`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    setIkutKursus(res.data || []);
  } catch (error) {
    setErrorIkutKursus("Gagal mengambil data ikut kursus");
    console.error(error);
  } finally {
    setLoadingIkutKursus(false);
  }
}, [axiosJWT, token]);

  const deleteIkutKursus = async (id) => {
  if (window.confirm("Yakin ingin menghapus data ikut kursus ini?")) {
    try {
      await axiosJWT.delete(`${BASE_URL}/ikutkursus/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      getIkutKursus();
    } catch (error) {
      console.error(error);
    }
  }
};

  const deleteCourse = async (id) => {
    if (window.confirm("Yakin ingin menghapus kursus ini?")) {
      try {
        await axiosJWT.delete(`${BASE_URL}/courses/${id}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        getCourses();
      } catch (error) {
        console.log(error);
      }
    }
  };

  const deleteUser = async (id) => {
    try {
      await axiosJWT.delete(`${BASE_URL}/users/${id}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      getUsers(); // Refresh list after delete
    } catch (error) {
      console.log(error);
    }
  };

    const togglePembayaran = async (item) => {
    try {
      const newStatus = item.pembayaran === "lunas" ? "pending" : "lunas";
      await axiosJWT.put(
        `${BASE_URL}/ikutkursus/${item.id}`,
        { pembayaran: newStatus },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      getIkutKursus();
    } catch (error) {
      console.error(error);
    }
  };

  const toggleStatus = async (item) => {
  try {
    const newStatus =
  item.status === "aktif" ? "nonaktif" :
  item.status === "nonaktif" ? "selesai" :
  "aktif";  // jika status "selesai" maka kembali ke "aktif"
    await axiosJWT.put(
      `${BASE_URL}/ikutkursus/${item.id}`,
      { status: newStatus },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    getIkutKursus(); // refresh data setelah update
  } catch (error) {
    console.error(error);
  }
};

  useEffect(() => {
    if (token && role === "admin") {
      getUsers();
      getCourses();
      getIkutKursus();

    }
  }, [token, role, getUsers, getCourses,getIkutKursus]);

return (
  <div className="mt-6 px-5">
    <section className="section">
      <div className="mb-5 has-text-centered">
        <h1 className="title is-3 has-text-primary">Dashboard Admin</h1>
        <p className="subtitle is-5">
          Halo, <strong>{name}</strong> ({role})
        </p>
        <button
          className="button is-link is-light"
          onClick={() => navigate("/dashboarduser")}
        >
          Ke Dashboard User
        </button>
      </div>

      {/* USERS */}
      <section className="box mb-6">
        <h2 className="title is-4 has-text-info">Daftar Pengguna</h2>
        <div className="table-container">
          <table className="table is-hoverable is-striped is-fullwidth">
            <thead>
              <tr>
                <th>No</th>
                <th>Nama</th>
                <th>Email</th>
                <th>Gender</th>
                <th style={{ minWidth: "140px" }}>Aksi</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user, idx) => (
                <tr key={user.id}>
                  <td>{idx + 1}</td>
                  <td>{user.name}</td>
                  <td>{user.email}</td>
                  <td>{user.gender}</td>
                  <td>
                    <Link
                      to={`/editikutkursus/${user.id}`}
                      className="button is-small is-info mr-2"
                    >
                      Edit
                    </Link>
                    <button
                      onClick={() => deleteUser(user.id)}
                      className="button is-small is-danger"
                    >
                      Hapus
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* COURSES */}
      <section className="box mb-6">
        <div className="level mb-4">
          <div className="level-left">
            <h2 className="title is-4 has-text-info">Daftar Kursus</h2>
          </div>
          <div className="level-right">
            <Link to="/add-course" className="button is-primary is-small">
              + Tambah Kursus
            </Link>
          </div>
        </div>

        <div className="table-container">
          <table className="table is-hoverable is-striped is-fullwidth is-bordered">
            <thead>
              <tr>
                <th>No</th>
                <th>Judul</th>
                <th>Guru</th>
                <th>Waktu (jam)</th>
                <th>Harga</th>
                <th>Kategori</th>
                <th>Deskripsi</th>
                <th>Gambar</th>
                <th style={{ minWidth: "140px" }}>Aksi</th>
              </tr>
            </thead>
            <tbody>
              {courses.map((course, idx) => (
                <tr key={course.id}>
                  <td>{idx + 1}</td>
                  <td>{course.Judul}</td>
                  <td>{course.Guru}</td>
                  <td>{course.Waktu}</td>
                  <td>{course.harga}</td>
                  <td>{course.Kategori}</td>
                  <td>
                    <div
                      style={{
                        maxWidth: "150px",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                      title={course.Deskripsi}
                    >
                      {course.Deskripsi}
                    </div>
                  </td>
                  <td>
                    {course.Img ? (
                      <figure className="image is-64x64">
                        <img
                          src={`${BASE_URL}/images/${course.Img}`}
                          alt={course.Judul}
                          style={{ objectFit: "cover" }}
                        />
                      </figure>
                    ) : (
                      <span className="has-text-grey-light">Tidak ada gambar</span>
                    )}
                  </td>
                  <td>
                    <Link
                      to={`/edit-kursus/${course.id}`}
                      className="button is-small is-info mr-2"
                    >
                      Edit
                    </Link>
                    <button
                      onClick={() => deleteCourse(course.id)}
                      className="button is-small is-danger"
                    >
                      Hapus
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* IKUT KURSUS */}
      <section className="box">
        <h2 className="title is-4 has-text-info">Daftar Ikut Kursus</h2>
        {loadingIkutKursus ? (
          <p>Loading...</p>
        ) : errorIkutKursus ? (
          <p className="has-text-danger">{errorIkutKursus}</p>
        ) : ikutKursus.length === 0 ? (
          <p>Belum ada data ikut kursus</p>
        ) : (
          <div className="table-container">
            <table className="table is-hoverable is-striped is-fullwidth is-bordered">
              <thead>
                <tr>
                  <th>No</th>
                  <th>IdUser</th>
                  <th>Judul Kursus</th>
                  <th>Status Pembayaran</th>
                  <th>Status Kursus</th>
                  <th style={{ minWidth: "180px" }}>Aksi</th>
                </tr>
              </thead>
              <tbody>
                {ikutKursus.map((item, idx) => (
                  <tr key={item.id}>
                    <td>{idx + 1}</td>
                    <td>{item.user?.name || "N/A"}</td>
                    <td>{item.kursus?.Judul || "N/A"}</td>
                    <td>
                      <span
                        className={
                          item.pembayaran === "lunas"
                            ? "tag is-success"
                            : "tag is-warning"
                        }
                      >
                        {item.pembayaran}
                      </span>
                    </td>
                    <td>
                      <span
                        className={
                          item.status === "aktif"
                            ? "tag is-primary"
                            : "tag is-light"
                        }
                      >
                        {item.status || "N/A"}
                      </span>
                    </td>
                    <td>
                      <button
                        className="button is-small is-warning mr-2"
                        onClick={() => togglePembayaran(item)}
                        title="Toggle Pembayaran"
                      >
                        Toggle Pembayaran
                      </button>
                      <button
                        className="button is-small is-info mr-2"
                        onClick={() => toggleStatus(item)}
                        title="Toggle Status Kursus"
                      >
                        Toggle Status
                      </button>
                      <button
                        className="button is-small is-danger"
                        onClick={() => deleteIkutKursus(item.id)}
                        title="Hapus Data"
                      >
                        Hapus
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </section>
  </div>
);
};

export default Dashboard;
