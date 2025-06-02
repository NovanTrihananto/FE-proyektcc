import React, { useState, useEffect, useCallback } from "react";
import { useNavigate, Link } from "react-router-dom";
import useAxiosToken from "../hooks/useAxiosToken";
import { BASE_URL } from "../utils";

const Dashboard = () => {
  const { axiosJWT, token, name, role } = useAxiosToken();
  const [users, setUsers] = useState([]);
  const [courses, setCourses] = useState([]);
  const [ikutKursus, setIkutKursus] = useState([]);
  const [loadingIkutKursus, setLoadingIkutKursus] = useState(false);
  const [errorIkutKursus, setErrorIkutKursus] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    if (role && role !== "admin") navigate("/dashboarduser");
  }, [role, navigate]);

  const getUsers = useCallback(async () => {
    try {
      const res = await axiosJWT.get(`${BASE_URL}/users`);
      setUsers(res.data.data || []);
    } catch (err) {
      console.error(err);
    }
  }, [axiosJWT]);

  const getCourses = useCallback(async () => {
    try {
      const res = await axiosJWT.get(`${BASE_URL}/courses`);
      setCourses(res.data || []);
    } catch (err) {
      console.error(err);
    }
  }, [axiosJWT]);

  const getIkutKursus = useCallback(async () => {
    try {
      setLoadingIkutKursus(true);
      const res = await axiosJWT.get(`${BASE_URL}/ikutkursus`);
      setIkutKursus(res.data || []);
    } catch (err) {
      setErrorIkutKursus("Gagal mengambil data ikut kursus");
      console.error(err);
    } finally {
      setLoadingIkutKursus(false);
    }
  }, [axiosJWT]);

  const deleteData = async (endpoint, callback) => {
    if (window.confirm("Yakin ingin menghapus data ini?")) {
      try {
        await axiosJWT.delete(`${BASE_URL}/${endpoint}`);
        callback();
      } catch (err) {
        console.error(err);
      }
    }
  };

  const toggleField = async (item, field, values, callback) => {
    try {
      const currentValue = item[field];
      const newValue =
        values[(values.indexOf(currentValue) + 1) % values.length];
      await axiosJWT.put(`${BASE_URL}/ikutkursus/${item.id}`, {
        [field]: newValue,
      });
      callback();
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    if (token && role === "admin") {
      getUsers();
      getCourses();
      getIkutKursus();
    }
  }, [token, role, getUsers, getCourses, getIkutKursus]);

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
                  <th>Aksi</th>
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
                        to={`/edit/${user.id}`}
                        className="button is-small is-info mr-2"
                      >
                        Edit
                      </Link>
                      <button
                        className="button is-small is-danger"
                        onClick={() =>
                          deleteData(`users/${user.id}`, getUsers)
                        }
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
                  <th>Aksi</th>
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
                    <td title={course.Deskripsi}>
                      <div
                        style={{
                          maxWidth: "150px",
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {course.Deskripsi}
                      </div>
                    </td>
                    <td>
                      {course.Img ? (
                        <figure className="image is-64x64">
                      <img
                        src={course.Img}
                        alt={course.Judul}
                        style={{ objectFit: "cover", width: "100%", height: "200px" }}
                      />
                        </figure>
                      ) : (
                        <span className="has-text-grey-light">
                          Tidak ada gambar
                        </span>
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
                        className="button is-small is-danger"
                        onClick={() =>
                          deleteData(`courses/${course.id}`, getCourses)
                        }
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
                    <th>Nama User</th>
                    <th>Judul Kursus</th>
                    <th>Status Pembayaran</th>
                    <th>Status Kursus</th>
                    <th>Aksi</th>
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
                          {item.status}
                        </span>
                      </td>
                      <td>
                        <button
                          className="button is-small is-warning mr-2"
                          onClick={() =>
                            toggleField(
                              item,
                              "pembayaran",
                              ["pending", "lunas"],
                              getIkutKursus
                            )
                          }
                        >
                          Toggle Pembayaran
                        </button>
                        <button
                          className="button is-small is-info mr-2"
                          onClick={() =>
                            toggleField(
                              item,
                              "status",
                              ["aktif", "nonaktif", "selesai"],
                              getIkutKursus
                            )
                          }
                        >
                          Toggle Status
                        </button>
                        <button
                          className="button is-small is-danger"
                          onClick={() =>
                            deleteData(`ikutkursus/${item.id}`, getIkutKursus)
                          }
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
