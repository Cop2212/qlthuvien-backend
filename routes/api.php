<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Models\User;
use Illuminate\Auth\Events\Verified;

/*
|--------------------------------------------------------------------------
| PUBLIC API
|--------------------------------------------------------------------------
*/

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login',    [AuthController::class, 'login']);

/*
|--------------------------------------------------------------------------
| EMAIL VERIFICATION
|--------------------------------------------------------------------------
| Link trong email sẽ gọi route này
| Sau khi xác nhận → redirect về FE
*/

Route::get('/email/verify/{id}/{hash}', function (Request $request, $id, $hash) {

    $user = User::findOrFail($id);

    // kiểm tra hash
    if (! hash_equals(
        (string) $hash,
        sha1($user->getEmailForVerification())
    )) {
        abort(403, 'Invalid verification link');
    }

    // nếu chưa verify thì verify
    if (! $user->hasVerifiedEmail()) {
        $user->markEmailAsVerified();
        event(new Verified($user));
    }

    return redirect()->away('http://localhost:4200/login?verified=1');
})->middleware('signed')->name('verification.verify');


/*
|--------------------------------------------------------------------------
| AUTHENTICATED API (Sanctum)
|--------------------------------------------------------------------------
*/

Route::middleware('auth:sanctum')->group(function () {

    Route::get('/me', [AuthController::class, 'me']);
    Route::post('/logout', [AuthController::class, 'logout']);

    // Gửi lại email xác nhận
    Route::post('/email/resend', function (Request $request) {

        if ($request->user()->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email đã được xác nhận'
            ]);
        }

        $request->user()->sendEmailVerificationNotification();

        return response()->json([
            'message' => 'Đã gửi lại email xác nhận'
        ]);
    });
});
