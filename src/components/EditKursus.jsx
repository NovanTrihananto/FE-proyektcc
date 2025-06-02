import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import useAxiosToken from "../hooks/useAxiosToken";
import { BASE_URL } from "../utils";

const EditKursus = () => {
  const { id } = useParams();
  const { axiosJWT, token } = useAxiosToken();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    Judul: "",
    Guru: "",
    Waktu: "",
    harga: "",
    Img: "",
    Deskripsi: "",
    Kategori: "",
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

 useEffect(() => {
  const fetchKursus = async () => {
    try {
      const res = await axiosJWT.get(`${BASE_URL}/courses/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      // Set data ke form
      setForm({
        Judul: res.data.Judul || "",
        Guru: res.data.Guru || "",
        Waktu: res.data.Waktu || "",
        harga: res.data.harga || "",
        Img: res.data.Img || "",
        Deskripsi: res.data.Deskripsi || "",
        Kategori: res.data.Kategori || "",
      });

      setLoading(false);
    } catch (err) {
      console.error(err);
      setError("Gagal mengambil data kursus");
      setLoading(false);
    }
  };

  if (token) {
    fetchKursus();
  }
}, [id, token, axiosJWT]);

  const handleChange = (e) => {
    setForm({
      ...form,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
    await axiosJWT.put(`${BASE_URL}/courses/${id}`, form, {
  headers: { Authorization: `Bearer ${token}` },
});

      navigate("/dashboard"); // Ganti sesuai route dashboard admin kamu
    } catch (err) {
      console.error(err);
      setError("Gagal menyimpan perubahan");
    }
  };

  if (loading) return <p>Memuat data...</p>;
  if (error) return <p className="has-text-danger">{error}</p>;

  return (
    <div className="container">
      <h1 className="title">Edit Kursus</h1>
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label className="label">Judul</label>
          <div className="control">
            <input
              className="input"
              type="text"
              name="Judul"
              value={form.Judul}
              onChange={handleChange}
              required
            />
          </div>
        </div>

        <div className="field">
          <label className="label">Guru</label>
          <div className="control">
            <input
              className="input"
              type="text"
              name="Guru"
              value={form.Guru}
              onChange={handleChange}
              required
            />
          </div>
        </div>

        <div className="field">
          <label className="label">Waktu</label>
          <div className="control">
            <input
              className="input"
              type="text"
              name="Waktu"
              value={form.Waktu}
              onChange={handleChange}
              required
            />
          </div>
        </div>

        <div className="field">
          <label className="label">Harga</label>
          <div className="control">
            <input
              className="input"
              type="text"
              name="harga"
              value={form.harga}
              onChange={handleChange}
              required
            />
          </div>
        </div>

        <div className="field">
          <label className="label">Gambar (URL)</label>
          <div className="control">
            <input
              className="input"
              type="text"
              name="Img"
              value={form.Img}
              onChange={handleChange}
              required
            />
          </div>
        </div>

        <div className="field">
          <label className="label">Deskripsi</label>
          <div className="control">
            <textarea
              className="textarea"
              name="Deskripsi"
              value={form.Deskripsi}
              onChange={handleChange}
              required
            ></textarea>
          </div>
        </div>

        <div className="field">
          <label className="label">Kategori</label>
          <div className="control">
            <input
              className="input"
              type="text"
              name="Kategori"
              value={form.Kategori}
              onChange={handleChange}
              required
            />
          </div>
        </div>

        <div className="field">
          <div className="control">
            <button type="submit" className="button is-primary">
              Simpan Perubahan
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default EditKursus;
