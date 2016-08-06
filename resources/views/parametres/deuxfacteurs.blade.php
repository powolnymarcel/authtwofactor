@extends('layouts.app')

@section('content')
    <div class="container">
        <div class="row">
            <div class="col-md-10 col-md-offset-1">
                <div class="panel panel-default">
                    <div class="panel-heading">Two factor settings</div>

                    <div class="panel-body">
                        <form class="form-horizontal" role="form" method="POST" action="{{ url('/settings/twofactor') }}">
                            <div class="form-group{{ $errors->has('two_factor_type') ? ' has-error' : '' }}">
                                <div class="col-md-6 col-md-offset-4">
                                    <select name="two_factor_type" id="two_factor_type" class="form-control">
                                        @foreach (config('twofactor.types') as $key => $name)
                                            <option value="{{ $key }}"{{ old('two_factor_type') === $key || Auth::user()->hasTwoFactorType($key) ? 'selected="selected"' : '' }}>{{ $name }}</option>
                                        @endforeach
                                    </select>

                                    @if ($errors->has('two_factor_type'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('two_factor_type') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>

                            <div class="form-group{{ $errors->has('phone_number_dialling_code') ? ' has-error' : '' }}">
                                <label for="phone_number_dialling_code" class="col-md-4 control-label">Dialling code</label>

                                <div class="col-md-6">
                                    <select name="phone_number_dialling_code" id="phone_number_dialling_code" class="form-control">
                                        <option value="">Select a dialling code</option>
                                        @foreach ($diallingCodes as $code)
                                            <option value="{{ $code->id }}"{{ old('phone_number_dialling_code') == $code->id || Auth::user()->hasDiallingCode($code->id) ? ' selected="selected"' : '' }}>{{ $code->name }} (+{{ $code->dialling_code }})</option>
                                        @endforeach
                                    </select>

                                    @if ($errors->has('phone_number_dialling_code'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('phone_number_dialling_code') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>

                            <div class="form-group{{ $errors->has('phone_number') ? ' has-error' : '' }}">
                                <label for="phone_number" class="col-md-4 control-label">Phone number</label>

                                <div class="col-md-6">
                                    <input id="phone_number" type="text" class="form-control" name="phone_number" value="{{ old('phone_number') ? old('phone_number') : Auth::user()->getPhoneNumber() }}">

                                    @if ($errors->has('phone_number'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('phone_number') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>

                            <div class="form-group">
                                <div class="col-md-6 col-md-offset-4">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fa fa-btn fa-sign-in"></i> Update
                                    </button>
                                </div>
                            </div>

                            {{ csrf_field() }}
                            {{ method_field('PUT') }}
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection
