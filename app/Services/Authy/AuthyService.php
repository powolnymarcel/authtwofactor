<?php

namespace App\Services\Authy;
use App\User;
use Authy\AuthyApi;
use Authy\AuthyFormatException;

use App\Services\Authy\Exceptions\InvalidTokenException;
use App\Services\Authy\Exceptions\RegistrationFailedException;
use App\Services\Authy\Exceptions\SmsRequestFailedException;

class AuthyService
{
    private $client;

    public function __construct(AuthyApi $client)
    {
        $this->client=$client;
    }

    public function inscriptionUser(User $user)
    {
        $user=$this->client->registerUser(
        $user->email,
        $user->phoneNumber->phone_number,
        $user->phoneNumber->diallingCode->dialling_code
    );
        if (!$user->ok()){
            //thorw exc
            throw new RegistrationFailedException;
        }

        return $user->id();
    }

    public function verificationToken($token, User $user=null)
    {
        try {
            $verification = $this->client->verifyToken(
                $user ? $user->authy_id : request()->session()->get('authy.authy_id'),
                $token
            );
        }catch (AuthyFormatException $e){
            //Throw exc
            throw new InvalidTokenException;

        }

        if(!$verification->ok()){
            //Throw exc
            throw new InvalidTokenException;
        }

        return true;

    }

    public function requeteSms(User $user)
    {
    $request=$this->client->requestSms($user->authy_id,[
        'force'=>true,
    ]);
        if (!$request->ok()){
            //Throw exc
            throw new SmsRequestFailedException;
        }
    }
}