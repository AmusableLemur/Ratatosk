<?php

use Silex\Application;

class RatatoskApp extends Application
{
    use Application\TwigTrait;
    use Application\SecurityTrait;
    use Application\UrlGeneratorTrait;
    use Application\MonologTrait;

    public function user()
    {
        $token = $this["security.token_storage"]->getToken();

        if (null === $token) {
            return null;
        }

        return $token->getUser();
    }
}
