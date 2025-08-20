import "dotenv/config";

import express from "express";
import axios from "axios";
import cors from "cors";
import { CookieJar } from "tough-cookie";
import { wrapper as axiosCookieJarSupport } from "axios-cookiejar-support";

const app = express();
const PORT = "3001";

const SUPERSET_DOMAIN = `https://supersettest-superset.dev.indocpilot.io`;
const SUPERSET_SERVICE_ACCOUNT_USERNAME =
  process.env.SUPERSET_SERVICE_ACCOUNT_USERNAME;
const SUPERSET_SERVICE_ACCOUNT_PASSWORD =
  process.env.SUPERSET_SERVICE_ACCOUNT_PASSWORD;

const cookieJar = new CookieJar();
// create axios instance that uses cookie jar
const axiosInstance = axios.create({
  jar: cookieJar,
  withCredentials: true,
});
axiosCookieJarSupport(axiosInstance); // modifies axios object to add interceptors that manages cookies and stores them in cookie jar

// Middleware
app.use(express.json()); // To parse JSON request bodies
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true, // Allow cookies/authorization headers to be sent
  })
);

// Get access token using login credentials or use provided keycloak token
async function getSupersetAccessToken() {
  try {
    const loginUrl = `${SUPERSET_DOMAIN}/api/v1/security/login`;
    // account credentials assigned to the back end aka service account that has authority to issue guest tokens
    const payload = {
      username: SUPERSET_SERVICE_ACCOUNT_USERNAME,
      password: SUPERSET_SERVICE_ACCOUNT_PASSWORD,
      provider: "db", // Assuming 'db' provider for the service account
      refresh: true,
    };

    const response = await axiosInstance.post(loginUrl, payload, {
      headers: { "Content-Type": "application/json" },
    });

    return response.data.access_token;
  } catch (error) {
    console.error(
      "Error getting Superset access token:",
      error.response ? error.response.data : error.message
    );
    throw new Error("Failed to get Superset access token");
  }
}

// Get CSRF token using access token, CSRF required to POST and get guest token
async function getSupersetCsrfToken(accessToken) {
  try {
    const csrfUrl = `${SUPERSET_DOMAIN}/api/v1/security/csrf_token/`;
    const response = await axiosInstance.get(csrfUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
      withCredentials: true,
    });
    return {
      csrfToken: response.data.result,
    };
  } catch (error) {
    console.error(
      "Error getting Superset CSRF token:",
      error.response ? error.response.data : error.message
    );
    throw new Error("Failed to get Superset CSRF token");
  }
}

// Use access and CSRF token to POST for guest token
async function generateGuestToken(
  accessToken,
  csrfToken,
  userSpecificFilters,
  resources
) {
  try {
    const guestTokenUrl = `${SUPERSET_DOMAIN}/api/v1/security/guest_token/`;
    const payload = {
      // embedded user's (front-end) credentials
      user: {
        username: `app_user_${Math.random().toString(36).substring(7)}`, // Unique username for the guest session
        first_name: "Embedded",
        last_name: "User",
      },
      resources,
      rls: userSpecificFilters, // Apply Row-Level Security based on your app's RBAC
    };

    const response = await axiosInstance.post(guestTokenUrl, payload, {
      headers: {
        "Content-Type": "application/json",
        Referer: "https://supersettest-superset.dev.indocpilot.io/",
        Authorization: `Bearer ${accessToken}`,
        "X-CSRF-Token": csrfToken,
        "X-CSRFToken": csrfToken,
      },
      withCredentials: true,
      // axios will handle cookies automatically if you use the same instance
      // or if the Superset API correctly sets them.
    });

    return response.data.token; // The actual guest token JWT
  } catch (error) {
    console.error(
      "Error generating guest token:",
      error.response ? error.response.data : error.message
    );
    throw new Error("Failed to generate guest token");
  }
}

app.post("/api/guest-token", async (req, res) => {
  // authentication / authorization logic - authentication not necessary, just provide keycloak token ?
  // parse user name from keycloak token
  // use username to fetch dashboard resources permitted for user
  // resource array passed to superset when requesting for guest token, backend just needs to contain the ID
  // const resources = [
  //   {
  //     type: "dashboard",
  //     id: "7b7fee3f-5319-459d-a636-fd9171620487",
  //   },
  //   {
  //     type: "dashboard",
  //     id: "8c42ba17-ed60-4ae1-94b2-fb0aef098d21",
  //   },
  // ];

  const resources = [];
  const userFilters = [];
  const accessToken = req.body.accessToken;

  try {
    // const accessToken = await getSupersetAccessToken();
    const { csrfToken } = await getSupersetCsrfToken(accessToken);
    const guestToken = await generateGuestToken(
      accessToken,
      csrfToken,
      userFilters, // Pass dynamic filters here
      resources
    );

    res.json({ token: guestToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`);
  console.log(`Superset Domain: ${SUPERSET_DOMAIN}`);
});
