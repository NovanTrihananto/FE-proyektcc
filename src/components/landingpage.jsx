import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { BASE_URL } from "../utils";

const LandingPage = ({ user }) => {
  const navigate = useNavigate();
  const [courses, setCourses] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCourses = async () => {
      try {
        const response = await axios.get(`${BASE_URL}/courses`);
        setCourses(response.data); // pastikan response.data adalah array course
        setLoading(false);
      } catch (error) {
        console.error("Gagal mengambil data kursus:", error);
        setLoading(false);
      }
    };

    fetchCourses();
  }, []);

  if (loading) return <p>Loading courses...</p>;

  return (
    
    <div>
      {/* Hero Section */}
      <section className="hero is-primary is-large">
        <div className="hero-body">
          <div className="container has-text-centered">
            <h1 className="title is-1">Belajar Skill Baru Hari Ini</h1>
            <h2 className="subtitle is-3">
              Ribuan kursus online berkualitas tinggi menanti Anda
            </h2>
            <button
              className="button is-large is-light"
              onClick={() => navigate(user ? "/dashboard" : "/login")}
            >
              Mulai Belajar Sekarang
            </button>
          </div>
        </div>
      </section>

      {/* Courses Section */}
      <section className="section">
        <div className="container">
          <h2 className="title is-2 has-text-centered mb-6">Kursus Populer</h2>
          <div className="columns is-multiline">
            {courses.length === 0 && <p>Tidak ada kursus tersedia.</p>}
            {courses.map((course) => (
              <div key={course.id} className="column is-one-third">
                <div className="card">
                  <div className="card-image">
                    <figure className="image is-4by3">
                      <img src={course.Img} alt={course.Judul} />
                    </figure>
                  </div>
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
                        <span className="tag is-primary">{course.Kategori}</span>
                        <span className="tag is-light">{course.Waktu} jam</span>
                      </div>
                      <div className="level">
                        <div className="level-left">
                          <div className="level-item">
                            <strong className="has-text-primary">Rp {course.harga}</strong>
                          </div>
                        </div>
                        <div className="level-right">
                          <div className="level-item">
                            <button
                              className="button is-primary"
                              onClick={() =>
                                navigate(user ? `/kursus/${course.id}` : "/login")
                              }
                            >
                              {user ? "Lihat Detail" : "Login untuk Mendaftar"}
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
        </div>
      </section>
    </div>
  );
};

export default LandingPage;
