import { useState, useEffect, useCallback } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { BASE_URL } from "../utils";
import useAxiosToken from "../hooks/useAxiosToken";

const EditUser = () => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [gender, setGender] = useState("Male");
  const [loading, setLoading] = useState(true);
  const { id } = useParams();
  const navigate = useNavigate();

  const { axiosJWT, token } = useAxiosToken();

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
      console.error("Gagal ambil data user:", error);
    } finally {
      setLoading(false);
    }
  }, [axiosJWT, id, token]);

  useEffect(() => {
    getUserById();
  }, [getUserById]);

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
      console.error("Gagal update user:", error);
    }
  };

  if (loading) {
    return <p className="has-text-centered mt-5">Loading data user...</p>;
  }

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
                required
              />
            </div>
          </div>

          <div className="field">
            <label className="label">Email</label>
            <div className="control">
              <input
                type="email"
                className="input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email"
                required
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

          <div className="field is-grouped">
            <div className="control">
              <button type="submit" className="button is-success">
                Update
              </button>
            </div>
            <div className="control">
              <Link to="/dashboard" className="button is-light">
                Kembali
              </Link>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditUser;
