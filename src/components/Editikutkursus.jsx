import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import useAxiosToken from "../hooks/useAxiosToken";
import { BASE_URL } from "../utils";

const EditIkutKursus = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { axiosJWT, token } = useAxiosToken();
  const [ikutKursus, setIkutKursus] = useState(null);
  const [pembayaran, setPembayaran] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchIkutKursus = async () => {
      try {
        const res = await axiosJWT.get(`${BASE_URL}/ikutkursus/${id}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setIkutKursus(res.data);
        setPembayaran(res.data.pembayaran || "");
        setLoading(false);
      } catch (err) {
        setError("Gagal mengambil data ikut kursus");
        setLoading(false);
      }
    };

    fetchIkutKursus();
  }, [id, axiosJWT, token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axiosJWT.put(
        `${BASE_URL}/ikutkursus/${id}`,
        { pembayaran },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      navigate("/dashboard"); // kembali ke dashboard setelah update
    } catch (err) {
      setError("Gagal mengupdate data");
      console.error(err);
    }
  };

  if (loading) return <p>Loading...</p>;
  if (error) return <p className="has-text-danger">{error}</p>;
  if (!ikutKursus) return <p>Data tidak ditemukan</p>;

  return (
    <div className="container mt-5">
      <h2 className="title is-4">Edit Ikut Kursus</h2>
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label className="label">Status Pembayaran</label>
          <div className="control">
            <div className="select">
              <select
                value={pembayaran}
                onChange={(e) => setPembayaran(e.target.value)}
                required
              >
                <option value="">Pilih status pembayaran</option>
                <option value="lunas">Lunas</option>
                <option value="pending">Pending</option>
              </select>
            </div>
          </div>
        </div>

        <button type="submit" className="button is-primary">
          Update
        </button>
      </form>
    </div>
  );
};

export default EditIkutKursus;
