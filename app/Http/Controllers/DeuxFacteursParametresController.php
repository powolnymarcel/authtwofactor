<?php

namespace App\Http\Controllers;

use App\DiallingCode;
use Illuminate\Http\Request;

use App\Http\Requests;

class DeuxFacteursParametresController extends Controller
{
    public function index()
    {
        return view('parametres.deuxfacteurs')->with([
        'diallingCodes' => DiallingCode::all(),
    ]);
}

public function update(Request $request)
{
    $this->validate($request, [
        'two_factor_type' => 'required|in:' . implode(',', array_keys(config('twofactor.types'))),
        'phone_number' => 'required_unless:two_factor_type,off',
        'phone_number_dialling_code' => 'required_unless:two_factor_type,off|exists:dialling_codes,id',
    ]);

    $user = $request->user();

    $user->updatePhoneNumber($request->phone_number, $request->phone_number_dialling_code);

    if (!$user->registeredForTwoFactorAuthentication()) {
        try {
            $authyId = Authy::registerUser($user);
            $user->authy_id = $authyId;
        } catch (RegistrationFailedException $e) {
            return redirect()->back();
        }
    }

    $user->two_factor_type = $request->two_factor_type;
    $user->save();

    return redirect()->back();
}
}
