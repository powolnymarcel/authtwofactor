<?php

namespace App;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'email', 'password',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    public function phoneNumber()
    {
        return $this->hasOne(PhoneNumber::class);
    }

    public function hasTwoFacteurAuthentificationActivee()
    {
        return $this->two_factor_type !== 'off';
    }

    public function hasSmsTwoFactorAuthenticationEnabled(){
        return $this->two_factor_type === 'sms';

    }
    public function hasTwoFactorType($type)
    {
        return $this->two_factor_type === $type;
    }

    public function hasDiallingCode($diallingCodeId)
    {
        if ($this->hasPhoneNumber() === false) {
            return false;
        }

        return $this->phoneNumber->diallingCode->id === $diallingCodeId;
    }

    public function getPhoneNumber()
    {
        if ($this->hasPhoneNumber() === false) {
            return false;
        }

        return $this->phoneNumber->phone_number;
    }

    public function hasPhoneNumber()
    {
        return $this->phoneNumber !== null;
    }

    public function registeredForTwoFactorAuthentication()
    {
        return $this->authy_id !== null;
    }

    public function updatePhoneNumber($phoneNumber, $phoneNumberDiallingCode)
    {
        $this->phoneNumber()->delete();

        if (!$phoneNumber) {
            return;
        }

        return $this->phoneNumber()->create([
            'phone_number' => $phoneNumber,
            'dialling_code_id' => $phoneNumberDiallingCode,
        ]);
    }
}
