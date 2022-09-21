<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Traits\ApiResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use App\Models\User;

class AuthController extends Controller
{
    use ApiResponse;

    public function login(LoginRequest $request){
        $validated = $request->validated();

        if(!Auth::attempt($validated)){
            return $this->apiError('Crendential not match', Response::HTTP_UNAUTHORIZED);
        }

        $user = User::where('email', $validated['email'])->first();
        $token = $user->createToken('auth_token')->plainTextToken;

        return $this->apiSuccess([
            'token' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ]);
    }
}
