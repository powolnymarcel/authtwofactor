<?php

namespace App\Http\Controllers\Auth;

use Authy;
use App\Services\Authy\Exceptions\SmsRequestFailedException;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Validator;
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Foundation\Auth\AuthenticatesAndRegistersUsers;

class AuthController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Registration & Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users, as well as the
    | authentication of existing users. By default, this controller uses
    | a simple trait to add these behaviors. Why don't you explore it?
    |
    */

    use AuthenticatesAndRegistersUsers, ThrottlesLogins;

    /**
     * Where to redirect users after login / registration.
     *
     * @var string
     */
    protected $redirectTo = '/';
    protected $redirectToToken = '/auth/token';

    /**
     * Create a new authentication controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware($this->guestMiddleware(), ['except' => 'logout']);
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|min:6|confirmed',
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);
    }
    protected function authenticated(Request $request,User $user)
    {
       
        if ($user->hasTwoFacteurAuthentificationActivee())
        {
            return $this->logoutAndRedirectToTokenEntry($request, $user);
        }

        return redirect()->intended($this->redirectPath());
    }

    protected function logoutAndRedirectToTokenEntry(Request $request,User $user)
    {
        Auth::guard($this->getGuard())->logout();

        $request->session()->put('authy',[
            'user_id'=>$user->id,
           'authy_id'=>$user->authy_id,
            'using_sms'=>false,
            'remember'=>$request->has('remember')
        ]);


        if ($user->hasSmsTwoFactorAuthenticationEnabled())
        {
            try{
                Authy::requeteSms($user);
            }catch (SmsRequestFailedException $e){
                return redirect()->back();
            }
            $request->session()->push(
                'authy.using_sms',true
            );
        }

        return redirect($this->redirectTokenPath());

    }

    protected function redirectTokenPath()
    {
        return $this->redirectToToken;
    }

}
