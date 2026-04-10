<?php

namespace App\Controllers\v1;
  
use App\Controllers\v1\BaseController;
use CodeIgniter\API\ResponseTrait;
use App\Models\UserModel;

class UserController extends BaseController
{
    use ResponseTrait;
    
    /**
     * [POST] /api/v1/user/login
     * 使用者登入
     * 
     */
    public function login()
    {
        $userModel = new UserModel();
   
        $email = $this->request->getJsonVar('email');
        $password = $this->request->getJsonVar('password');

        $user = $userModel->where('email', $email)->first();
   
        if(is_null($user)) {
            return $this->respond(['error' => 'Invalid username or password.'], 401);
        }
   
        $pwd_verify = password_verify($password, $user['password']);
   
        if(!$pwd_verify) {
            return $this->respond(['error' => 'Invalid username or password.'], 401);
        }
  
        $key = getenv('JWT_SECRET');
        $iat = time(); // current timestamp value
        $exp = $iat + 86400; // add 24 hours to timestamp value
  
        $payload = array(
            "iss" => "Anser",
            "aud" => "User",
            "sub" => "AnserOrchestration",
            "iat" => $iat, //Time the JWT issued at
            "exp" => $exp, // Expiration time of token
            "email" => $user['email'],
            "u_key" => (int)$user['id']
        );
          
        $token = \Firebase\JWT\JWT::encode($payload, $key, 'HS256');
  
        $response = [
            'message' => 'Login Succesful',
            'token' => $token
        ];
          
        return $this->respond($response, 200);
    }

    /**
     * [GET] /api/v1/user
     * 使用者驗證與取得使用者資訊
     * 
     */
    public function verify()
    {
        $key = getenv('JWT_SECRET');
        $header = $this->request->getHeader("Authorization");

        if(!$header) {
            return $this->respond(['error' => 'No token provided.'], 401);
        }

        $token = $header->getValue();
        try {
            $decoded = \Firebase\JWT\JWT::decode($token, new \Firebase\JWT\Key($key, 'HS256'));
        } catch (\Firebase\JWT\ExpiredException $e) {
            return $this->respond(['error' => 'Provided token is expired.'], 401);
        } catch (\Exception $ex) {
            return $this->respond(['error' => 'Invalid token provided.'], 401);
        }

        $response = [
            'message' => 'Token is valid',
            'data' => $decoded
        ];

        return $this->respond($response, 200);
    }
  
}