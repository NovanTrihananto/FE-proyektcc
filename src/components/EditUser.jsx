import { useState, useEffect, useCallback } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { BASE_URL } from "../utils";
import useAxiosToken from "../hooks/useAxiosToken";

const EditUser = () => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [gender, setGender] = useState("");
  const { id } = useParams();
  const navigate = useNavigate();

  // Pakai custom hook untuk axios dengan auto refresh token
  const { axiosJWT, token } = useAxiosToken();

  // Fungsi ambil user berdasarkan ID, dibungkus useCallback supaya bisa dipakai di useEffect
  const getUserById = useCallback(async () => {
    try {
      const response = await axiosJWT.get(`${BASE_URL}/users/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const { name, email, gender } = response.data.data;
      setName(name);
      setEmail(email);
      setGender(gender);
    } catch (error) {
      console.log(error);
    }
  }, [axiosJWT, id, token]);

  useEffect(() => {
    if (token) {
      getUserById();
    }
  }, [token, getUserById]);

  const updateUser = async (e) => {
    e.preventDefault();
    try {
      await axiosJWT.put(
        `${BASE_URL}/users/${id}`,
        { name, email, gender },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      navigate("/dashboard");
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div className="columns mt-5 is-centered">
      <div className="column is-half">
        <form onSubmit={updateUser}>
          <div className="field">
            <label className="label">Name</label>
            <div className="control">
              <input
                type="text"
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Name"
              />
            </div>
          </div>

          <div className="field">
            <label className="label">Email</label>
            <div className="control">
              <input
                type="text"
                className="input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email"
              />
            </div>
          </div>

          <div className="field">
            <label className="label">Gender</label>
            <div className="control">
              <div className="select is-fullwidth">
                <select value={gender} onChange={(e) => setGender(e.target.value)}>
                  <option value="Male">Male</option>
                  <option value="Female">Female</option>
                </select>
              </div>
            </div>
          </div>

          <div className="field">
            <button type="submit" className="button is-success mr-2">
              Update
            </button>
            <Link to="/dashboard" className="button is-text">
              Kembali
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditUser;
