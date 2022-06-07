<?php

namespace Yadahan\AuthenticationLog\Listeners;

use Illuminate\Auth\Events\Logout;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Yadahan\AuthenticationLog\AuthenticationLog;

class LogSuccessfulLogout
{
    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    public $request;

    /**
     * Create the event listener.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Handle the event.
     *
     * @param  Logout  $event
     * @return void
     */
    public function handle(Logout $event)
    {
        if ($event->user) {
            $user = $event->user;
            if (!($user instanceof Model)) {
                // 모델이 아니면 건너뛰기
                return;
            }
            $ip = $this->request->ip();
            $userAgent = $this->request->userAgent();
            $authenticationLog = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->first();

            if (! $authenticationLog) {
                $authenticationLog = new AuthenticationLog([
                    'ip_address' => $ip,
                    'user_agent' => $userAgent,
                ]);
            }

            $authenticationLog->logout_at = Carbon::now();

            $user->authentications()->save($authenticationLog);
        }
    }
}
