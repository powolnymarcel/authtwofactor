@extends('layouts.app')

@section('content')
    <div class="container">
        <div class="row">
            <div class="col-md-10 col-md-offset-1">
                <div class="panel panel-default">
                    <div class="panel-heading">Two factor authentication</div>

                    <div class="panel-body">
                        <form class="form-horizontal" role="form" method="POST" action="{{ url('/auth/token') }}">
                            {{ csrf_field() }}

                            <div class="form-group{{ $errors->has('token') ? ' has-error' : '' }}">
                                <label for="token" class="col-md-4 control-label">Token</label>

                                <div class="col-md-6">
                                    <input id="token" type="text" class="form-control" name="token" value="{{ old('token') }}" autofocus>

                                    @if ($errors->has('token'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('token') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>

                            <div class="form-group">
                                <div class="col-md-6 col-md-offset-4">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fa fa-btn fa-sign-in"></i> Valider le token
                                    </button>

                                    @if (request()->session()->get('authy.using_sms'))
                                        <hr>
                                        <p class="help-block">Token non reçu? <a href="{{ url('/auth/token/resend') }}">Ré essayer </a></p>
                                    @endif
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection
