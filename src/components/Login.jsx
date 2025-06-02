import React, { useState } from "react";
import axios from "axios";
import { Link, useNavigate } from "react-router-dom";
import { BASE_URL } from "../utils";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");
  const navigate = useNavigate();

  const Auth = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${BASE_URL}/login`, {
        email,
        password,
      });
      navigate("/dashboard");
    } catch (error) {
      if (error.response) {
        setMsg(error.response.data.message);
      } else {
        setMsg("Terjadi kesalahan saat login");
      }
    }
  };

  return (
    <section className="section">
      <div className="container">
        <div className="columns is-centered">
          <div className="column is-one-third">
            <form onSubmit={Auth} className="box">
              <h1 className="title has-text-centered">Masuk</h1>

              {msg && (
                <div className="notification is-danger is-light">{msg}</div>
              )}

              <div className="field">
                <label className="label">Email atau Username</label>
                <div className="control">
                  <input
                    type="text"
                    className="input"
                    placeholder="email@example.com atau username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="field">
                <label className="label">Password</label>
                <div className="control">
                  <input
                    type="password"
                    className="input"
                    placeholder="********"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="field">
                <button className="button is-primary is-fullwidth">
                  Masuk
                </button>
              </div>

              <div className="has-text-centered mt-4">
                <p>
                  Belum punya akun?{" "}
                  <Link to="/register" className="has-text-link">
                    Daftar di sini
                  </Link>
                </p>
              </div>
            </form>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Login;
