import { useState, useEffect, useRef, useCallback } from "react";
import axios from "axios";
import { jwtDecode } from "jwt-decode";
import { useNavigate } from "react-router-dom";
import { BASE_URL } from "../utils";

const useAxiosToken = () => {
  const [token, setToken] = useState("");
  const [expire, setExpire] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("");
  const [userId, setUserId] = useState("");
  const navigate = useNavigate();

  const axiosJWT = useRef(axios.create()).current;

  const refreshToken = useCallback(async () => {
    try {
      const response = await axios.get(`${BASE_URL}/token`);
      const accessToken = response.data.accessToken;
      setToken(accessToken);
      const decoded = jwtDecode(accessToken);
      setName(decoded.name);
      setExpire(decoded.exp);
      setRole(decoded.role);
      setUserId(decoded.id);
    } catch (error) {
      setToken("");
      navigate("/login");
    }
  }, [navigate]);

  const setupInterceptor = useCallback(() => {
    const interceptor = axiosJWT.interceptors.request.use(
      async (config) => {
        const currentDate = new Date();

        if (expire * 1000 < currentDate.getTime()) {
          try {
            const response = await axios.get(`${BASE_URL}/token`);
            const accessToken = response.data.accessToken;
            setToken(accessToken);

            const decoded = jwtDecode(accessToken);
            setName(decoded.name);
            setExpire(decoded.exp);
            setRole(decoded.role);
            setUserId(decoded.id);

            config.headers.Authorization = `Bearer ${accessToken}`;
          } catch (err) {
            console.error("Interceptor failed to refresh token:", err);
            navigate("/");
            return Promise.reject(err);
          }
        } else {
          config.headers.Authorization = `Bearer ${token}`;
        }

        return config;
      },
      (error) => {
        console.error("Interceptor request error:", error);
        navigate("/");
        return Promise.reject(error);
      }
    );

    return () => {
      axiosJWT.interceptors.request.eject(interceptor);
    };
  }, [axiosJWT, expire, navigate, token]);

  useEffect(() => {
    refreshToken();
    const ejectInterceptor = setupInterceptor();
    return () => {
      ejectInterceptor();
    };
  }, [refreshToken, setupInterceptor]);

  return { axiosJWT, token, name, role, userId };
};

export default useAxiosToken;
