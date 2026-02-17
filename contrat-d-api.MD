
# CONTRAT D'API ET REPARTITION DES TACHES

**Date de l'examen** : 17 février 2026  
**Groupe 1** : Raphael, Davidson, Noura  
**Services** :  
- **auth-service** service principal qui tournera sur le port `3000`  
- **data-service** MICROSERVICE_PEPPER_DEUX qui tournera sur le port  `3001`

---

## Repartition des taches :
## RAPHAEL : JWT Maison et Rotaion
## DAVIDSON :  RATE LIMITER ET POW
## NOURA : MICROSERVICE + PEPPER + COMMUNICATION INTERNE

## Variables d’environnement 

```env
SECRET=
PEPPER_MAIN=
PEPPER_SECONDARY=
PORT_AUTH=
PORT_DATA=
```

---

## 1. Auth-Service (`http://localhost:3000`)

### Endpoints Publics

| Endpoint          | Méthode | Description                  | Body (JSON)                              | Headers                  | Réponse Succès (200)                     | Codes Erreur          |
|-------------------|---------|------------------------------|------------------------------------------|--------------------------|------------------------------------------|-----------------------|
| `/auth/login`     | `POST`  | Connexion utilisateur        | `{ "username": "string", "password": "string" }` | Aucun                   | `{ "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }` | 401 Unauthorized     |
| `/auth/rotate`    | `POST`  | Rotation de token            | `{}` (vide)                              | `Authorization: Bearer <old_token>` | `{ "token": "eyJ..." }`                 | 401, 403             |

### Endpoints Protégés (JWT + Rate Limiter + PoW)

**Middlewares dans l’ordre obligatoire** :  
1. Vérification signature  
2. Vérification expiration  
3. Rate limiter (basé sur `jti`)  
4. Proof of Work (`X-POW-Nonce`)

| Endpoint             | Méthode | Description                          | Body | Headers Requis                                      | Réponse Succès                  | Codes Erreur                  |
|----------------------|---------|--------------------------------------|------|-----------------------------------------------------|---------------------------------|-------------------------------|
| `/secure-data`      | `GET`   | Données sécurisées (appelle le microservice) | `{}` | `Authorization: Bearer <token>`<br>`X-POW-Nonce: <nonce>` | `{ "data": "contenu sécurisé" }` | 401, 403 (PoW), 429 (Rate)   |

**Règles spécifiques** :
- **Rate Limiter** : 10 requêtes / 30 secondes par `jti` → `429` + `console.log("ALERTE MAXIMALE")`
- **Proof of Work** : `SHA256(token + nonce)` commence par `"0000"` → `403` + `console.log("ALERTE MAXIMALE POW")`
- Mot **« pollution »** à ajouter quelque part dans le code

**Message au démarrage** : `console.log("Bonjour le monde")`

---

## 2. Data-Service (`http://localhost:3001` – MICROSERVICE_PEPPER_DEUX)

**Endpoints Internes Uniquement**

| Endpoint            | Méthode | Description                          | Body | Headers Requis                          | Réponse Succès                  | Codes Erreur          |
|---------------------|---------|--------------------------------------|------|-----------------------------------------|---------------------------------|-----------------------|
| `/internal/data`   | `GET`   | Endpoint sécurisé inter-microservice | `{}` | `X-INTERNAL-TOKEN: <internal_jwt>`     | `{ "secure": true }`           | 403 Forbidden        |

**Règles** :
- N’accepte **QUE** les tokens internes (signés avec `SECRET + PEPPER_SECONDARY`)
- Refuse tous les tokens utilisateurs
- **Message au démarrage** : `console.log("Hello World")`

---

## 3. Flux Inter-Microservices

```
Client → POST /secure-data (auth-service)
    ↓ (vérif user token + génération token interne)
Auth-service → GET /internal/data (data-service avec X-INTERNAL-TOKEN)
    ↓
Data-service → { "secure": true }
    ↓
Auth-service → Client
```

---

## 4. Exemples de Requêtes (Postman / cURL)

### 1. Login
```http
POST http://localhost:3000/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password123"
}
```

### 2. Secure Data (protégé)
```http
GET http://localhost:3000/secure-data
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-POW-Nonce: 1234567890abcdef
```

### 3. Appel interne (depuis auth-service)
```http
GET http://localhost:3001/internal/data
X-INTERNAL-TOKEN: eyJ... (token généré avec PEPPER_SECONDARY)
```

---

