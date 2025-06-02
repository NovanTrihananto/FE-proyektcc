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
  const tokenRef = useRef("");
  const navigate = useNavigate();

  const axiosJWT = useRef(axios.create()).current;
  const axiosRefresh = useRef(axios.create()).current;
const expireRef = useRef("");

const refreshToken = useCallback(async () => {
  try {
    const response = await axiosRefresh.get(`${BASE_URL}/token`, {
      withCredentials: true,
    });
    const accessToken = response.data.accessToken;
    const decoded = jwtDecode(accessToken);

    setToken(accessToken);
    tokenRef.current = accessToken;
    setName(decoded.name);
    setExpire(decoded.exp);
    expireRef.current = decoded.exp;
    setRole(decoded.role);
    setUserId(decoded.id);
  } catch (error) {
    setToken("");
    tokenRef.current = "";
    if (error.response?.status === 401) {
      navigate("/login");
    } else {
      console.error("Failed to refresh token:", error);
    }
  }
}, [navigate]);

const setupInterceptor = useCallback(() => {
  const interceptor = axiosJWT.interceptors.request.use(
    async (config) => {
      const currentDate = new Date();

      if (expireRef.current * 1000 < currentDate.getTime()) {
        try {
          const response = await axiosRefresh.get(`${BASE_URL}/token`, {
            withCredentials: true,
          });
          const accessToken = response.data.accessToken;
          const decoded = jwtDecode(accessToken);

          setToken(accessToken);
          tokenRef.current = accessToken;
          setName(decoded.name);
          setExpire(decoded.exp);
          expireRef.current = decoded.exp;
          setRole(decoded.role);
          setUserId(decoded.id);

          config.headers.Authorization = `Bearer ${accessToken}`;
        } catch (err) {
          console.error("Interceptor failed to refresh token:", err);
          if (err.response?.status === 401) {
            navigate("/login");
          }
          return Promise.reject(err);
        }
      } else {
        config.headers.Authorization = `Bearer ${tokenRef.current}`;
      }

      return config;
    },
    (error) => Promise.reject(error)
  );

  return () => {
    axiosJWT.interceptors.request.eject(interceptor);
  };
}, [axiosJWT, navigate]);


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
