import React, { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import useAxiosToken from "../hooks/useAxiosToken";
import { BASE_URL } from "../utils";

const DashboardUser = () => {
  const { axiosJWT, token, name, role, userId } = useAxiosToken();
  const [courses, setCourses] = useState([]);
  const [enrolledCourses, setEnrolledCourses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [isLoadingEnroll, setIsLoadingEnroll] = useState(false);
  const navigate = useNavigate();

  // Filter berdasarkan status
  const activeCourses = enrolledCourses.filter(
    (ikut) => ikut.status === "aktif"
  );

  const nonActiveCourses = enrolledCourses.filter(
    (ikut) => ikut.status === "nonaktif"
  );

  const completedCourses = enrolledCourses.filter(
    (ikut) => ikut.status === "selesai"
  );

  useEffect(() => {
    if (role && role !== "admin" && role !== "user") {
      navigate("/landingpage");
    }
  }, [role, navigate]);

  const getCourses = useCallback(async () => {
    try {
      const res = await axiosJWT.get(`${BASE_URL}/courses`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setCourses(res.data || []);
    } catch (err) {
      console.error(err);
      setError("Gagal mengambil data kursus");
    }
  }, [axiosJWT, token]);

  const getEnrolledCourses = useCallback(async () => {
    try {
      const res = await axiosJWT.get(`${BASE_URL}/ikutkursus/${userId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setEnrolledCourses(res.data || []);
    } catch (err) {
      console.error(err);
      setError("Gagal mengambil data kursus yang diikuti");
    }
  }, [axiosJWT, token, userId]);

  useEffect(() => {
    if (token && (role === "user" || role === "admin")) {
      Promise.all([getCourses(), getEnrolledCourses()]).finally(() =>
        setLoading(false)
      );
    }
  }, [token, role, getCourses, getEnrolledCourses]);

  const isEnrolled = (courseId) => {
    return enrolledCourses.some((ikut) => ikut.idKursus === courseId);
  };

  const handleEnroll = async (course) => {
    try {
      setIsLoadingEnroll(true);
      setMsg("");
      await axiosJWT.post(
        `${BASE_URL}/ikutkursus`,
        { idUser: userId, idKursus: course.id },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setMsg(`Berhasil daftar kursus: ${course.Judul}`);
      await getEnrolledCourses();
    } catch (err) {
      const errMsg = err.response?.data?.msg || "Gagal daftar kursus";
      setMsg(`Gagal daftar: ${errMsg}`);
      console.error(err);
    } finally {
      setIsLoadingEnroll(false);
    }
  };

  const myCourses = enrolledCourses.map((ikut) => {
    const courseDetail = courses.find((c) => c.id === ikut.idKursus);
    return {
      ...ikut,
      ...courseDetail,
    };
  });

  if (loading) return <p>Loading...</p>;
  if (error) return <p className="has-text-danger">{error}</p>;

  return (
    <section className="section">
      <div className="container">
        <h1 className="title">Dashboard</h1>

        <div className="columns">
          <div className="column">
            <div className="notification is-primary">
              <h2 className="subtitle">Selamat datang, {name}!</h2>
              <p>Anda telah mendaftar di {enrolledCourses.length} kursus.</p>
            </div>
          </div>
        </div>

        <div className="columns is-multiline">
          {/* Kursus Aktif */}
          <div className="column is-one-quarter">
            <div className="box has-text-centered">
              <p className="title is-1 has-text-primary">{activeCourses.length}</p>
              <p className="subtitle">Kursus Aktif</p>
            </div>
          </div>
          {/* Kursus Nonaktif */}
          <div className="column is-one-quarter">
            <div className="box has-text-centered">
              <p className="title is-1 has-text-warning">{nonActiveCourses.length}</p>
              <p className="subtitle">Kursus Nonaktif</p>
            </div>
          </div>
          {/* Kursus Selesai */}
          <div className="column is-one-quarter">
            <div className="box has-text-centered">
              <p className="title is-1 has-text-success">{completedCourses.length}</p>
              <p className="subtitle">Kursus Selesai</p>
            </div>
          </div>
          {/* Total Kursus */}
          <div className="column is-one-quarter">
            <div className="box has-text-centered">
              <p className="title is-1 has-text-info">{courses.length}</p>
              <p className="subtitle">Total Kursus</p>
            </div>
          </div>
        </div>

        {/* Kursus Saya */}
        <h2 className="title is-4">Kursus Saya</h2>
        <div className="columns is-multiline">
          {myCourses.length === 0 ? (
            <p className="ml-4">Kamu belum mendaftar kursus apa pun.</p>
          ) : (
            myCourses.map((course) => (
              <div key={course.idKursus} className="column is-one-third">
                <div className="card">
                  {course.Img && (
                    <div className="card-image">
                      <figure className="image is-4by3">
                      <img src={course.Img} alt={course.Judul} />
                      </figure>
                    </div>
                  )}
                  <div className="card-content">
                    <div className="media">
                      <div className="media-content">
                        <p className="title is-5">{course.Judul}</p>
                        <p className="subtitle is-6">oleh {course.Guru}</p>
                      </div>
                    </div>
                    <div className="content">
                      <p>{course.Deskripsi}</p>
                      <div className="tags">
                        {course.Kategori && (
                          <span className="tag is-primary">{course.Kategori}</span>
                        )}
                        {course.Waktu && (
                          <span className="tag is-light">{course.Waktu} jam</span>
                        )}
                      </div>
                      <p className="mt-2">
                        Status Kursus:{" "}
                        <strong
                          className={
                            course.status === "selesai"
                              ? "has-text-success"
                              : course.status === "nonaktif"
                              ? "has-text-warning"
                              : ""
                          }
                        >
                          {course.status}
                        </strong>
                      </p>
                      <p>
                        Status Pembayaran:{" "}
                        <strong
                          className={
                            course.pembayaran === "lunas"
                              ? "has-text-success"
                              : "has-text-warning"
                          }
                        >
                          {course.pembayaran || "Belum bayar"}
                        </strong>
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Semua Kursus */}
        <h2 className="title is-4 mt-6">Semua Kursus</h2>
        <div className="columns is-multiline">
          {courses.map((course) => (
            <div key={course.id} className="column is-one-third">
              <div className="card">
                {course.Img && (
                  <div className="card-image">
                    <figure className="image is-4by3">
                        <img src={course.Img} alt={course.Judul} />
                    </figure>
                  </div>
                )}
                <div className="card-content">
                  <div className="media">
                    <div className="media-content">
                      <p className="title is-5">{course.Judul}</p>
                      <p className="subtitle is-6">oleh {course.Guru}</p>
                    </div>
                  </div>
                  <div className="content">
                    <p>{course.Deskripsi}</p>
                    <div className="tags">
                      {course.Kategori && (
                        <span className="tag is-primary">{course.Kategori}</span>
                      )}
                      {course.Waktu && (
                        <span className="tag is-light">{course.Waktu} jam</span>
                      )}
                    </div>
                    <div className="level">
                      <div className="level-left">
                        <div className="level-item">
                          <strong className="has-text-primary">
                            Rp {course.harga || "Gratis"}
                          </strong>
                        </div>
                      </div>
                      <div className="level-right">
                        <div className="level-item">
                          <button
                            className={`button ${
                              isEnrolled(course.id) ? "is-success" : "is-primary"
                            }`}
                            onClick={() => handleEnroll(course)}
                            disabled={isEnrolled(course.id) || isLoadingEnroll}
                          >
                            {isEnrolled(course.id)
                              ? "✓ Terdaftar"
                              : isLoadingEnroll
                              ? "Mendaftar..."
                              : "Daftar"}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {msg && <p className="has-text-info mt-4">{msg}</p>}
      </div>
    </section>
  );
};

export default DashboardUser;
