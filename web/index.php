<?php

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

require_once __DIR__."/../vendor/autoload.php";

$app = new RatatoskApp();
$app["debug"] = true;

$app->register(new Silex\Provider\DoctrineServiceProvider(), array(
    "db.options" => array(
        "driver" => "pdo_sqlite",
        "path" => __DIR__."/../app.db",
    ),
));

$app->register(new Silex\Provider\MonologServiceProvider(), [
    "monolog.logfile" => __DIR__."/../logs/dev.log",
]);

$app->register(new Silex\Provider\SecurityServiceProvider(), [
    "security.firewalls" => [
        "login" => [
            "pattern" => "^/(login|register)$",
        ],
        "chat" => [
            "pattern" => "^.+$",
            "form" => [
                "login_path" => "/login",
                "check_path" => "/user/login_check",
            ],
            "logout" => [
                "logout_path" => "/user/logout",
                "invalidate_session" => true
            ],
            "users" => function () use ($app) {
                return new UserProvider($app["db"]);
            },
        ],
    ],
]);

$app->register(new Silex\Provider\SessionServiceProvider());

$app->register(new Silex\Provider\TwigServiceProvider(), [
    "twig.path" => __DIR__."/../views",
]);

$app->get("/login", function(Request $request) use ($app) {
    return $app->render("login.html.twig", [
        "error" => $app["security.last_error"]($request),
        "last_username" => $app["session"]->get("_security.last_username"),
    ]);
});

$app->get("/register", function(Request $request) use ($app) {
    return $app->render("register.html.twig");
})->bind("register");

$app->post("/register", function(Request $request) use ($app) {
    $user = new User($request->get("username"), "", ["ROLE_USER"], true, true, true, true);
    $encoder = $app["security.encoder_factory"]->getEncoder($user);
    $password = $encoder->encodePassword($request->get("password"), $user->getSalt());

    $query = $app["db"]->prepare(
        "INSERT INTO users (username, password, roles)
        VALUES (:username, :password, \"ROLE_USER\")"
    );

    $query->bindValue("username", $request->get("username"));
    $query->bindParam("password", $password);

    try {
        $query->execute();
    } catch (Exception $e) {
        return $app->render("register.html.twig", [
            "error" => "Username already exists"
        ]);
    }

    // If sign-up is successful we sign in automatically and forward to the main page
    $token = new UsernamePasswordToken(
        $user,
        $user->getPassword(),
        "chat",
        $user->getRoles()
    );
    $app["security.token_storage"]->setToken($token);

    $app["session"]->set("_security_main", serialize($token));
    $app["session"]->save();

    return $app->redirect("/");
});

$app->get("/", function() use ($app) {
    $query = $app["db"]->prepare(
        "SELECT c.name, c.public FROM conversations c
        JOIN participants p ON p.conversation_id = c.id
        JOIN users u ON p.user_id = u.id
        WHERE c.public OR u.username = :username"
    );

    $query->bindParam("username", $app->user()->getUsername());
    $query->execute();

    return $app->render("index.html.twig", [
        "conversations" => $query->fetchAll(),
    ]);
})->bind("home");

$app->run();
