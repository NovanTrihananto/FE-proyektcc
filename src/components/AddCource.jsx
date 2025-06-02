import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import useAxiosToken from "../hooks/useAxiosToken";
import { BASE_URL } from "../utils";

const AddCourse = () => {
  const { axiosJWT, token, role } = useAxiosToken();
  const navigate = useNavigate();

  const [Judul, setJudul] = useState("");
  const [Guru, setGuru] = useState("");
  const [Waktu, setWaktu] = useState("");
  const [harga, setHarga] = useState("");
    const [Kategori, setKategori] = useState("");
   const [Deskripsi, setDeskripsi] = useState("");
  const [Img, setImg] = useState(null);
  const [preview, setPreview] = useState(null);

  // Hanya admin yang bisa akses
  useEffect(() => {
    if (role && role !== "admin") {
      navigate("/landingpage");
    }
  }, [role, navigate]);

  // Preview gambar
  const handleImageChange = (e) => {
    const file = e.target.files[0];
    setImg(file);
    setPreview(URL.createObjectURL(file));
  };

  // Submit form
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      formData.append("Judul", Judul);
      formData.append("Guru", Guru);
      formData.append("Waktu", Waktu);
      formData.append("harga", harga);
      formData.append("Kategori", Kategori);
      formData.append("Deskripsi", Deskripsi);
      formData.append("Img", Img);

      await axiosJWT.post(`${BASE_URL}/courses`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });

      navigate("/dashboard"); // kembali ke dashboard setelah berhasil tambah
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="columns mt-5 is-centered">
      <div className="column is-half">
        <h2 className="title is-4">Tambah Kursus Baru</h2>
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label className="label">Judul</label>
            <div className="control">
              <input className="input" type="text" value={Judul} onChange={(e) => setJudul(e.target.value)} required />
            </div>
          </div>

          <div className="field">
            <label className="label">Guru</label>
            <div className="control">
              <input className="input" type="text" value={Guru} onChange={(e) => setGuru(e.target.value)} required />
            </div>
          </div>

          <div className="field">
            <label className="label">Waktu (jam)</label>
            <div className="control">
              <input className="input" type="number" value={Waktu} onChange={(e) => setWaktu(e.target.value)} required />
            </div>
          </div>

          <div className="field">
            <label className="label">Harga</label>
            <div className="control">
              <input className="input" type="number" value={harga} onChange={(e) => setHarga(e.target.value)} required />
            </div>
          </div>

            <div className="field">
            <label className="label">Kategori</label>
            <div className="control">
              <input className="input" type="text" value={Kategori} onChange={(e) => setKategori(e.target.value)} required />
            </div>
          </div>

          <div className="field">
            <label className="label">deskripsi</label>
            <div className="control">
              <input className="input" type="text" value={Deskripsi} onChange={(e) => setDeskripsi(e.target.value)} required />
            </div>
          </div>

          <div className="field">
            <label className="label">Gambar</label>
            <div className="control">
              <input className="input" type="file" accept="image/*" onChange={handleImageChange} required />
            </div>
            {preview && (
              <figure className="image is-128x128 mt-2">
                <img src={preview} alt="Preview" />
              </figure>
            )}
          </div>

          <div className="field mt-4">
            <button className="button is-primary" type="submit">
              Simpan Kursus
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddCourse;
