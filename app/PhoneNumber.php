<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class PhoneNumber extends Model
{
    protected $table='phone_numbers';


    protected $fillable=[
        'phone_number',
        'dialling_code_id'
    ];

    public function diallingCode(){
        return $this->hasOne(DiallingCode::class,'id','dialling_code_id');
    }

    public function user(){
        return $this->belongsTo(User::class);
    }


}
