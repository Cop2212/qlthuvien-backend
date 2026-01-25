<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Auth\Events\Registered;

class AuthController extends Controller
{
    /**
     * ĐĂNG KÝ
     */
    public function register(Request $request)
    {
        $data = $request->validate([
            'name'     => 'required|string|max:255',
            'email'    => 'required|email|unique:users,email',
            'password' => 'required|min:6',
        ]);

        $user = User::create([
            'name'     => $data['name'],
            'email'    => $data['email'],
            'password' => Hash::make($data['password']),
        ]);

        event(new Registered($user));

        return response()->json([
            'message' => 'Đăng ký thành công. Vui lòng kiểm tra email để xác nhận tài khoản.'
        ], 201);
    }

    /**
     * ĐĂNG NHẬP
     */
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json(['message' => 'Sai thông tin đăng nhập'], 401);
        }

        $user = Auth::user();
        /** @var \App\Models\User $user */
        if (!$user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Bạn cần xác nhận email trước khi đăng nhập'
            ], 403);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'user'  => $user,
            'token' => $token,
        ]);
    }

    /**
     * LẤY USER ĐANG ĐĂNG NHẬP
     */
    public function me(Request $request)
    {
        return response()->json($request->user());
    }

    /**
     * ĐĂNG XUẤT
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Đã đăng xuất'
        ]);
    }
}
