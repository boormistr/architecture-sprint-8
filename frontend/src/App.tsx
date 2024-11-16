import React from 'react';
import Keycloak from 'keycloak-js';
import { ReactKeycloakProvider } from '@react-keycloak/web';
import ReportPage from './components/ReportPage';

const keycloak = new Keycloak({
  url: 'http://localhost:8080',
  realm: 'reports-realm',
  clientId: 'reports-frontend',
});

const App: React.FC = () => {
  return (
    <ReactKeycloakProvider
      authClient={keycloak}
      initOptions={{
        onLoad: 'login-required',
        pkceMethod: 'S256',
      }}
    >
      <ReportPage />
    </ReactKeycloakProvider>
  );
};

export default App;
