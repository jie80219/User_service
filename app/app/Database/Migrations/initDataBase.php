<?php

namespace App\Database\Migrations;

use App\Database\Migrations\History;
use App\Database\Migrations\User;

class initDataBase
{
    public static function initDataBase($group = "default")
    {
		\Config\Services::migrations()->setGroup($group);
        // self::createTable($group);
        return "success";

    }

    public static function createTable($group)
    {
        (new History(\Config\Database::forge($group)))->up();
        (new User(\Config\Database::forge($group)))->up();
    }
}
