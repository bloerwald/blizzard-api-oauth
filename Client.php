<?php
/**
 * Note : Code is released under the GNU LGPL
 *
 * Please do not change the header of this file
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Lesser General Public License for more details.
 */

/**
 * Based off Light PHP wrapper for the OAuth 2.0 protocol.
 *
 *
 * @author      Joe Foster (Ulminia) <ulminia@gmail.com>

 */
namespace OAuth2;

require_once( 'GrantType/IGrantType.php');
require_once( 'GrantType/AuthorizationCode.php');
require_once( 'GrantType/ClientCredentials.php');


class oauthApi
{
    /**
     * Different AUTH method
     */
    const AUTH_TYPE_URI                 = 0;
    const AUTH_TYPE_AUTHORIZATION_BASIC = 1;
    const AUTH_TYPE_FORM                = 2;

    /**
     * Different Access token type
     */
    const ACCESS_TOKEN_URI      = 0;
    const ACCESS_TOKEN_BEARER   = 1;
    const ACCESS_TOKEN_OAUTH    = 2;
    const ACCESS_TOKEN_MAC      = 3;

    /**
    * Different Grant types
    */
    const GRANT_TYPE_AUTH_CODE          = 'authorization_code';
    const GRANT_TYPE_PASSWORD           = 'password';
    const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_id';
    const GRANT_TYPE_REFRESH_TOKEN      = 'refresh_token';
    const GRANT_TYPE_C_C                = 'client_credentials';

    /**
     * HTTP Methods
     */
    const HTTP_METHOD_GET    = 'GET';
    const HTTP_METHOD_POST   = 'POST';
    const HTTP_METHOD_PUT    = 'PUT';
    const HTTP_METHOD_DELETE = 'DELETE';
    const HTTP_METHOD_HEAD   = 'HEAD';
    const HTTP_METHOD_PATCH  = 'PATCH';

    /**
     * HTTP Form content types
     */
    const HTTP_FORM_CONTENT_TYPE_APPLICATION = 0;
    const HTTP_FORM_CONTENT_TYPE_MULTIPART = 1;

    /**
     * Client ID
     *
     * @var string
     */
    protected $client_id = null;

    /**
     * Client Secret
     *
     * @var string
     */
    protected $client_secret = null;

    /**
     * Client Authentication method
     *
     * @var int
     */
    protected $client_auth = self::AUTH_TYPE_URI;

    /**
     * Access Token
     *
     * @var string
     */
    protected $access_token = null;

    /**
     * Access Token Type
     *
     * @var int
     */
    protected $access_token_type = self::ACCESS_TOKEN_URI;

    /**
     * Access Token Secret
     *
     * @var string
     */
    protected $access_token_secret = null;

    /**
     * Access Token crypt algorithm
     *
     * @var string
     */
    protected $access_token_algorithm = null;

    /**
     * Access Token Parameter name
     *
     * @var string
     */
    protected $access_token_param_name = 'access_token';

    /**
     * The path to the certificate file to use for https connections
     *
     * @var string  Defaults to .
     */
    protected $certificate_file = null;

    /**
     * cURL options
     *
     * @var array
     */
    protected $curl_options = array();

    /**
     *  Redirect uri
     *
     */
    public $redirect_uri = '';


    /**
     *  Base url setting
     *
     */
    public $baseurl = array(

            'US' => array(
                'urlbase'                   => 'https://us.api.blizzard.com',
                'AUTHORIZATION_ENDPOINT'    => 'https://oauth.battle.net/authorize',
                'TOKEN_ENDPOINT'            => 'https://oauth.battle.net/token',
                'ACCOUNT_ENDPOINT'          => 'https://oauth.battle.net',
            ),
            'EU' => array(
                'urlbase'                   => 'https://eu.api.blizzard.com',
                'AUTHORIZATION_ENDPOINT'    => 'https://oauth.battle.net/authorize',
                'TOKEN_ENDPOINT'            => 'https://oauth.battle.net/token',
                'ACCOUNT_ENDPOINT'          => 'https://oauth.battle.net',
            ),
            'KR' => array(
                'urlbase'                   => 'https://kr.api.blizzard.com',
                'AUTHORIZATION_ENDPOINT'    => 'https://oauth.battle.net/authorize',
                'TOKEN_ENDPOINT'            => 'https://oauth.battle.net/token',
                'ACCOUNT_ENDPOINT'          => 'https://oauth.battle.net',
            ),
            'TW' => array(
                'urlbase'                   => 'https://tw.api.blizzard.com',
                'AUTHORIZATION_ENDPOINT'    => 'https://oauth.battle.net/authorize',
                'TOKEN_ENDPOINT'            => 'https://oauth.battle.net/token',
                'ACCOUNT_ENDPOINT'          => 'https://oauth.battle.net',
            ),
            'CN' => array(
                'urlbase'                   => 'https://gateway.battlenet.com.cn',
                'AUTHORIZATION_ENDPOINT'    => 'https://oauth.battle.net.cn/authorize',
                'TOKEN_ENDPOINT'            => 'https://oauth.battle.net.cn/token',
                'ACCOUNT_ENDPOINT'          => 'https://oauth.battlenet.com.cn',
            ),
            'SEA' => array(
                'urlbase'                   => 'https://sea.api.blizzard.com',
                'AUTHORIZATION_ENDPOINT'    => 'https://oauth.battle.net/authorize',
                'TOKEN_ENDPOINT'            => 'https://oauth.battle.net/token',
                'ACCOUNT_ENDPOINT'          => 'https://oauth.battle.net',
            ),
    );

    public $ignore_cache = false;
    /**
     *  region setting
     *
     */
    public $region = '';

     /**
     *  Locale setting
     *
     */
    public $locale = '';

    /*
    *   some tracking bits for people
    */
    public $usage = array(
                'type'              => '',
                'url'               => '',
                'responce_code'     => '',
                'content_type'      => '',
                'locale'            => '',
            );
    public $cache;
    public $item;

    public $errno = CURLE_OK;
    public $error = '';
    /**
     * Construct
     *
     * @param string $client_id Client ID
     * @param string $client_secret Client Secret
     * @param int    $client_auth (AUTH_TYPE_URI, AUTH_TYPE_AUTHORIZATION_BASIC, AUTH_TYPE_FORM)
     * @param string $certificate_file Indicates if we want to use a certificate file to trust the server. Optional, defaults to null.
     * @return void
     */
    public function __construct($client_id, $client_secret, $region, $locale, $redirect_uri)
    {
        if (!extension_loaded('curl')) {
            throw new Exception('The PHP exention curl must be installed to use this library.', Exception::CURL_NOT_FOUND);
        }

        $r = preg_replace('/http:/', 'https:', $redirect_uri);
        $client_auth            = self::AUTH_TYPE_URI;
        $this->client_id        = $client_id;
        $this->client_secret    = $client_secret;
        $this->region           = $region;
        $this->locale           = $locale;
        $this->client_auth      = $client_auth;
        $this->redirect_uri     = $r;

        $this->setAccessToken ($this->getAccessToken (self::GRANT_TYPE_C_C)['access_token']);
        $this->setAccessTokenType (self::ACCESS_TOKEN_BEARER);

    }

    public function set_region($region)
    {
        $this->region = $region;
    }

    /**
     * Get the client Id
     *
     * @return string Client ID
     */
    public function getClientId()
    {
        return $this->client_id;
    }

    /**
     * Get the client Secret
     *
     * @return string Client Secret
     */
    public function getClientSecret()
    {
        return $this->client_secret;
    }

    /**
     * getAuthenticationUrl
     *
     * @param array  $extra_parameters  Array of extra parameters like scope or state (Ex: array('scope' => null, 'state' => ''))
     * @return string URL used for authentication
     */
    public function getAuthenticationUrl(array $extra_parameters = array())
    {
        $parameters = array_merge(array(
            'response_type' => 'code',
            'client_id'     => $this->client_id,
            'scope'         => 'wow.profile',
            'auth_flow'     => 'auth_code',
            'redirect_uri'  => $this->redirect_uri
        ), $extra_parameters);
        return $this->baseurl[$this->region]['AUTHORIZATION_ENDPOINT']
            . '?' . http_build_query($parameters, null, '&');
    }

    /**
     * getAccessToken
     *
     * @param int    $grant_type        Grant Type ('authorization_code', 'password', 'client_credentials', 'refresh_token', or a custom code (@see GrantType Classes)
     * @param array  $parameters        Array sent to the server (depend on which grant type you're using)
     * @return array Array of parameters required by the grant_type (CF SPEC)
     */
    public function getAccessToken($grant_type, array $parameters = array())
    {
        $token_endpoint = $this->baseurl[$this->region]['TOKEN_ENDPOINT'];
        $parameters['redirect_uri'] = $this->redirect_uri;

        if (!$grant_type) {
            throw new InvalidArgumentException('The grant_type is mandatory.', InvalidArgumentException::INVALID_GRANT_TYPE);
        }
        $grantTypeClassName = $this->convertToCamelCase($grant_type);
        $grantTypeClass =  __NAMESPACE__ . '\\GrantType\\' . $grantTypeClassName;
        if (!class_exists($grantTypeClass)) {
            throw new InvalidArgumentException('Unknown grant type \'' . $grant_type . '\' ['.$grantTypeClass.']', InvalidArgumentException::INVALID_GRANT_TYPE);
        }
        $grantTypeObject = new $grantTypeClass();
        $grantTypeObject->validateParameters($parameters);
        if (!defined($grantTypeClass . '::GRANT_TYPE')) {
            throw new Exception('Unknown constant GRANT_TYPE for class ' . $grantTypeClassName, Exception::GRANT_TYPE_ERROR);
        }
        $parameters['grant_type'] = $grantTypeClass::GRANT_TYPE;
        $http_headers = array();
        switch ($this->client_auth) {
            case self::AUTH_TYPE_URI:
            case self::AUTH_TYPE_FORM:
                $parameters['client_id'] = $this->client_id;
                $parameters['client_secret'] = $this->client_secret;
                break;
            case self::AUTH_TYPE_AUTHORIZATION_BASIC:
                $parameters['client_id'] = $this->client_id;
                $http_headers['Authorization'] = 'Basic ' . base64_encode($this->client_id .  ':' . $this->client_secret);
                break;
            default:
                throw new Exception('Unknown client auth type.', Exception::INVALID_CLIENT_AUTHENTICATION_TYPE);
        }

        $result = $this->executeRequest($token_endpoint, $parameters, self::HTTP_METHOD_POST, $http_headers, self::HTTP_FORM_CONTENT_TYPE_APPLICATION);

        return $result;
    }

    /**
     * setToken
     *
     * @param string $token Set the access token
     * @return void
     */
    public function setAccessToken($token)
    {
        $this->access_token = $token;
    }

    /**
     * Set the client authentication type
     *
     * @param string $client_auth (AUTH_TYPE_URI, AUTH_TYPE_AUTHORIZATION_BASIC, AUTH_TYPE_FORM)
     * @return void
     */
    public function setClientAuthType($client_auth)
    {
        $this->client_auth = $client_auth;
    }

    /**
     * Set an option for the curl transfer
     *
     * @param int   $option The CURLOPT_XXX option to set
     * @param mixed $value  The value to be set on option
     * @return void
     */
    public function setCurlOption($option, $value)
    {
        $this->curl_options[$option] = $value;
    }

    /**
     * Set multiple options for a cURL transfer
     *
     * @param array $options An array specifying which options to set and their values
     * @return void
     */
    public function setCurlOptions($options)
    {
        $this->curl_options = array_merge($this->curl_options, $options);
    }

    /**
     * Set the access token type
     *
     * @param int $type Access token type (ACCESS_TOKEN_BEARER, ACCESS_TOKEN_MAC, ACCESS_TOKEN_URI)
     * @param string $secret The secret key used to encrypt the MAC header
     * @param string $algorithm Algorithm used to encrypt the signature
     * @return void
     */
    public function setAccessTokenType($type, $secret = null, $algorithm = null)
    {
        $this->access_token_type = $type;
        $this->access_token_secret = $secret;
        $this->access_token_algorithm = $algorithm;
    }


    protected function _buildUrl($path, $params = array())
    {
        // allways called in all api calls
        $params['apikey'] = $this->client_id;
        if (isset($this->access_token))
        {
            $params['access_token'] = $this->access_token;
        }
        //set for translation
        $params['locale'] = $this->locale;
        if ($this->_request_namespace($path))
            $params['namespace'] = $this->_request_namespace($path).'-'.mb_strtolower($this->region, 'UTF-8');
        if ($path == 'account')
        {
            $url = $this->baseurl[$this->region]['ACCOUNT_ENDPOINT'];
        }
        else
        {
            $url = $this->baseurl[$this->region]['urlbase'];
        }
        //$url .= $path;
        $url .= self::_buildtype($path,$params);
        unset($params['name']);
        unset($params['server']);
        $url .= (count($params)) ? '?' . $this->_build_strings($params, '&') : '';
        $this->usage = array (
            'type'      => $path,
            'url'       => $url,
            'locale'    => $this->locale
        );
        //echo $url;
        return $url;

    }

    function _build_strings($params, $sep)
    {
        $r = array();
        foreach($params as $key=>$val)
        {
            $r[] = $key.'='.$val;
        }
        $e = implode($sep, $r);
        return $e;
    }

    /**
    *   Type of call uri build
    *   $class - type of call
    *   $fields - array of data (name,server,size)
    **/
    public function _buildtype($class,$fields)
    {
        if (isset ($fields['server'])) $fields['realm'] = $fields['server'];
        foreach ($fields as $key => $value)
        {
          $fields[$key] = rawurlencode ($value);
        }
        switch (str_replace('-', '_', $class))
        {
            case 'account':
                return '/oauth/userinfo';

            /* Account Profile API */
            case 'wowprofile':
            case 'account_profile_summary':
                return '/profile/user/wow';
            case 'protected_character_profile_summary':
                return '/profile/user/wow/protected-character/'.$fields['realmId'].'-'.$fields['characterId'];
            case 'account_collections_index':
                return '/profile/user/wow/collections';
            case 'account_mounts_collection_summary':
                return '/profile/user/wow/collections/mounts';
            case 'account_pets_collection_summary':
                return '/profile/user/wow/collections/pets';

            /*  Achievement API */
            case 'achievement_categories_index':
                return '/data/wow/achievement-category/index';
            case 'achievement_category':
                return '/data/wow/achievement-category/'.$fields['achievementCategoryId'];
            case 'achievements_index':
                return '/data/wow/achievement/index';
            case 'achievement':
                if (isset($fields['id']) && !isset($fields['achievementId'])) $fields['achievementId'] = $fields['id'];
                return '/data/wow/achievement/'.$fields['achievementId'];
            case 'achievement_media':
                return '/data/wow/media/achievement/'.$fields['achievementId'];

            /*  Auction House API */
            case 'auctions':
                return '/data/wow/connected-realm/'.$fields['connectedRealmId'].'/auctions';
            case 'commodities':
                return '/data/wow/auctions/commodities';

            /*  Azerite Essence API */
            case 'azerite_essences_index':
                return '/data/wow/azerite-essence/index';
            case 'azerite_essence':
                return '/data/wow/azerite-essence/'.$fields['azeriteEssenceId'];
            case 'azerite_essence_search':
                return '/data/wow/search/azerite-essence';
            case 'azerite_essence_media':
                return '/data/wow/media/azerite-essence/'.$fields['azeriteEssenceId'];

            /*  Connected Realm API */
            case 'connected_realms_index':
                return '/data/wow/connected-realm/index';
            case 'connected_realm':
                return '/data/wow/connected-realm/'.$fields['connectedRealmId'];
            case 'connected_realms_search':
                return '/data/wow/search/connected-realm';

            /*  Covenant API */
            case 'covenant_index':
                return '/data/wow/covenant/index';
            case 'covenant':
                return '/data/wow/covenant/'.$fields['covenantId'];
            case 'covenant_media':
                return '/data/wow/media/covenant/'.$fields['covenantId'];
            case 'soulbind_index':
                return '/data/wow/covenant/soulbind/index';
            case 'soulbind':
                return '/data/wow/covenant/soulbind/'.$fields['soulbindId'];
            case 'conduit_index':
                return '/data/wow/covenant/conduit/index';
            case 'conduit':
                return '/data/wow/covenant/conduit/'.$fields['conduitId'];

            /*  Creature API */
            case 'creature_families_index':
                return '/data/wow/creature-family/index';
            case 'creature_family':
                return '/data/wow/creature-family/'.$fields['creatureFamilyId'];
            case 'creature_types_index':
                return '/data/wow/creature-type/index';
            case 'creature_type':
                return '/data/wow/creature-type/'.$fields['creatureTypeId'];
            case 'creature':
                return '/data/wow/creature/'.$fields['creatureId'];
            case 'creature_search':
                return '/data/wow/search/creature';
            case 'creature_display_media':
                return '/data/wow/media/creature-display/'.$fields['creatureDisplayId'];
            case 'creature_family_media':
                return '/data/wow/media/creature-family/'.$fields['creatureFamilyId'];

            /*  Guild Crest API */
            case 'guild_crest_components_index':
                return '/data/wow/guild-crest/index';
            case 'guild_crest_border_media':
                return '/data/wow/media/guild-crest/border/'.$fields['borderId'];
            case 'guild_crest_emblem_media':
                return '/data/wow/media/guild-crest/emblem/'.$fields['emblemId'];

            /*  Item API */
            case 'item_classes_index':
                return '/data/wow/item-class/index';
            case 'item_class':
                return '/data/wow/item-class/'.$fields['itemClassId'];
            case 'item_sets_index':
                return '/data/wow/item-set/index';
            case 'item_set':
                return '/data/wow/item-set/'.$fields['itemSetId'];
            case 'item_subclass':
                return '/data/wow/item-class/'.$fields['itemClassId'].'/item-subclass/'.$fields['itemSubclassId'];
            case 'item':
                return '/data/wow/item/'.$fields['itemId'];
            case 'item_media':
                return '/data/wow/media/item/'.$fields['itemId'];
            case 'item_search':
                return '/data/wow/search/item';

            /*  Journal API */
            case 'journal_expansions_index':
                return '/data/wow/journal-expansion/index';
            case 'journal_expansion':
                return '/data/wow/journal-expansion/'.$fields['journalExpansionId'];
            case 'journal_encounters_index':
                return '/data/wow/journal-encounter/index';
            case 'journal_encounter':
                return '/data/wow/journal-encounter/'.$fields['journalEncounterId'];
            case 'journal_encounter_search':
                return '/data/wow/search/journal-encounter';
            case 'journal_instances_index':
                return '/data/wow/journal-instance/index';
            case 'journal_instance':
                return '/data/wow/journal-instance/'.$fields['journalInstanceId'];
            case 'journal_instance_media':
                return '/data/wow/media/journal-instance/'.$fields['journalInstanceId'];

            /*  Media Search API */
            case 'media_search':
                return '/data/wow/search/media';

            /*  Modified Crafting API */
            case 'modified_crafting_index':
                return '/data/wow/modified-crafting/index';
            case 'modified_crafting_category_index':
                return '/data/wow/modified-crafting/category/index';
            case 'modified_crafting_category':
                return '/data/wow/modified-crafting/category/'.$fields['categoryId'];
            case 'modified-crafting-reagent-slot-type-index':
                return '/data/wow/modified-crafting/reagent-slot-type/index';
            case 'modified-crafting-reagent-slot-type':
                return '/data/wow/modified-crafting/reagent-slot-type/'.$fields['slotTypeId'];

            /*  Mount API */
            case 'mounts_index':
                return '/data/wow/mount/index';
            case 'mount':
                return '/data/wow/mount/'.$fields['mountId'];
            case 'mount_search':
                return '/data/wow/search/mount';

            /*  Mythic Keystone Affix API */
            case 'mythic_keystone_affixes_index':
                return '/data/wow/keystone-affix/index';
            case 'mythic_keystone_affix':
                return '/data/wow/keystone-affix/'.$fields['keystoneAffixId'];
            case 'mythic_keystone_affix_media':
                return '/data/wow/media/keystone-affix/'.$fields['keystoneAffixId'];

            /*  Mythic Keystone Dungeon API */
            case 'mythic_keystone_dungeons_index':
                return '/data/wow/mythic-keystone/dungeon/index';
            case 'mythic_keystone_dungeon':
                return '/data/wow/mythic-keystone/dungeon/'.$fields['dungeonId'];
            case 'mythic_keystone_index':
                return '/data/wow/mythic-keystone/index';
            case 'mythic_keystone_periods_index':
                return '/data/wow/mythic-keystone/period/index';
            case 'mythic_keystone_period':
                return '/data/wow/mythic-keystone/period/'.$fields['periodId'];
            case 'mythic_keystone_seasons_index':
                return '/data/wow/mythic-keystone/season/index';
            case 'mythic_keystone_season':
                return '/data/wow/mythic-keystone/season/'.$fields['seasonId'];

            /*  Mythic Keystone Leaderboard API */
            case 'mythic_keystone_leaderboards_index':
                return '/data/wow/connected-realm/'.$fields['connectedRealmId'].'/mythic-leaderboard/index';
            case 'mythic_keystone_leaderboard':
                return '/data/wow/connected-realm/'.$fields['connectedRealmId'].'/mythic-leaderboard/'.$fields['dungeonId'].'/period/'.$fields['period'];

            /*  Mythic Raid Leaderboard API */
            case 'mythic_raid_leaderboard':
                return '/data/wow/leaderboard/hall-of-fame/'.$fields['raid'].'/'.$fields['faction'];

            /*  Pet API */
            case 'pets_index':
                return '/data/wow/pet/index';
            case 'pet':
                return '/data/wow/pet/'.$fields['petId'];
            case 'pet_media':
                return '/data/wow/media/pet/'.$fields['petId'];
            case 'pet_abilities_index':
                return '/data/wow/pet-ability/index';
            case 'pet_ability':
                return '/data/wow/pet-ability/'.$fields['petAbilityId'];
            case 'pet_ability_media':
                return '/data/wow/media/pet-ability/'.$fields['petAbilityId'];

            /*  Playable Class API */
            case 'playable_classes_index':
                return '/data/wow/playable-class/index';
            case 'playable_class':
                return '/data/wow/playable-class/'.$fields['classId'];
            case 'playable_class_media':
                return '/data/wow/media/playable-class/'.$fields['playableClassId'];
            case 'pvp_talent_slots':
                return '/data/wow/playable-class/'.$fields['classId'].'/pvp-talent-slots';

            /*  Playable Race API */
            case 'playable_races_index':
                return '/data/wow/playable-race/index';
            case 'playable_race':
                return '/data/wow/playable-race/'.$fields['playableRaceId'];

            /*  Playable Specialization API */
            case 'playable_specializations_index':
                return '/data/wow/playable-specialization/index';
            case 'playable_specialization':
                return '/data/wow/playable-specialization/'.$fields['specId'];
            case 'playable_specialization_media':
                return '/data/wow/media/playable-specialization/'.$fields['specId'];

            /*  Power Type API */
            case 'power_types_index':
                return '/data/wow/power-type/index';
            case 'power_type':
                return '/data/wow/power-type/'.$fields['powerTypeId'];

            /*  Profession API */
            case 'professions_index':
                return '/data/wow/profession/index';
            case 'profession':
                return '/data/wow/profession/'.$fields['professionId'];
            case 'profession_media':
                return '/data/wow/media/profession/'.$fields['professionId'];
            case 'profession_skill_tier':
                return '/data/wow/profession/'.$fields['professionId'].'/skill-tier/'.$fields['skillTierId'];
            case 'recipe':
                return '/data/wow/recipe/'.$fields['recipeId'];
            case 'recipe_media':
                return '/data/wow/media/recipe/'.$fields['recipeId'];

            /*  PvP Season API */
            case 'pvp_seasons_index':
                return '/data/wow/pvp-season/index';
            case 'pvp_season':
                return '/data/wow/pvp-season/'.$fields['pvpSeasonId'];
            case 'pvp_leaderboards_index':
                return '/data/wow/pvp-season/'.$fields['pvpSeasonId'].'/pvp-leaderboard/index';
            case 'pvp_leaderboard':
                return '/data/wow/pvp-season/'.$fields['pvpSeasonId'].'/pvp-leaderboard/'.$fields['pvpBracket'];
            case 'pvp_rewards_index':
                return '/data/wow/pvp-season/'.$fields['pvpSeasonId'].'/pvp-reward/index';

            /*  PvP Tier API */
            case 'pvp_tier_media':
                return '/data/wow/media/pvp-tier/'.$fields['pvpTierId'];
            case 'pvp_tiers_index':
                return '/data/wow/pvp-tier/index';
            case 'pvp_tier':
                return '/data/wow/pvp-tier/'.$fields['pvpTierId'];

            /*  Quest API */
            case 'quests_index':
                return '/data/wow/quest/index';
            case 'quest':
                return '/data/wow/quest/'.$fields['questId'];
            case 'quest_categories_index':
                return '/data/wow/quest/category/index';
            case 'quest_category':
                return '/data/wow/quest/category/'.$fields['questCategoryId'];
            case 'quest_areas_index':
                return '/data/wow/quest/area/index';
            case 'quest_area':
                return '/data/wow/quest/area/'.$fields['questAreaId'];
            case 'quest_types_index':
                return '/data/wow/quest/type/index';
            case 'quest_type':
                return '/data/wow/quest/type/'.$fields['questTypeId'];

            /*  Realm API */
            case 'realms_index':
                return '/data/wow/realm/index';
            case 'realm':
                return '/data/wow/realm/'.$fields['server'];
            case 'realm_search':
                return '/data/wow/search/realm';

            /*  Region API */
            case 'regions_index':
                return '/data/wow/region/index';
            case 'region':
                return '/data/wow/region/'.$fields['regionId'];

            /*  Reputations API */
            case 'reputation_factions_index':
                return '/data/wow/reputation-faction/index';
            case 'reputation_faction':
                return '/data/wow/reputation-faction/'.$fields['reputationFactionId'];
            case 'reputation_tiers_index':
                return '/data/wow/reputation-tiers/index';
            case 'reputation_tiers':
                return '/data/wow/reputation-tiers/'.$fields['reputationTiersId'];

            /*  Spell API */
            case 'spell':
                return '/data/wow/spell/'.$fields['spellId'];
            case 'spell_media':
                return '/data/wow/media/spell/'.$fields['spellId'];
            case 'spell_search':
                return '/data/wow/search/spell';

            /*  Talent API */
            case 'talents_index':
                return '/data/wow/talent/index';
            case 'talent':
                return '/data/wow/talent/'.$fields['talentId'];
            case 'pvp_talents_index':
                return '/data/wow/pvp-talent/index';
            case 'pvp_talent':
                return '/data/wow/pvp-talent/'.$fields['pvpTalentId'];
            case 'talent_tree_index':
                return '/data/wow/talent-tree/index';
            case 'talent_tree':
                return '/data/wow/talent-tree/'.$fields['talentTreeId'].'/playable-specialization/'.$fields['specId'];
            case 'talent_tree_nodes':
                return '/data/wow/talent-tree/'.$fields['talentTreeId'];

            /*  Tech Talent API */
            case 'tech_talent_tree_index':
                return '/data/wow/tech-talent-tree/index';
            case 'tech_talent_tree':
                return '/data/wow/tech-talent-tree/'.$fields['techTalentTreeId'];
            case 'tech_talent_index':
                return '/data/wow/tech-talent/index';
            case 'tech_talent':
                return '/data/wow/tech-talent/'.$fields['techTalentId'];
            case 'tech_talent_media':
                return '/data/wow/media/tech-talent/'.$fields['techTalentId'];

            /*  Title API */
            case 'titles_index':
                return '/data/wow/title/index';
            case 'title':
                return '/data/wow/title/'.$fields['titleId'];

            /*  WoW Token API */
            case 'wow_token_index':
                return '/data/wow/token/index';

            /*  Character Achievements API */
            case 'character_achievements_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/achievements';
            case 'character_achievement_statistics':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/achievements/statistics';

            /*  Character Appearance API */
            case 'character_appearance_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/appearance';

            /*  Character Collections API */
            case 'character_collections':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/collections';
            case 'character_collections_mounts':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/collections/mounts';
            case 'character_collections_pets':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/collections/pets';

            /*  Character Encounters API */
            case 'character_encounters_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/encounters';
            case 'character_dungeons':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/encounters/dungeons';
            case 'character_raids':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/encounters/raids';

            /*  Character Equipment API */
            case 'character_equipment_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/equipment';

            /*  Character Hunter Pets API */
            case 'character_hunter_pets_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/hunter-pets';

            /*  Character Media API */
            case 'character_media_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/character-media';

            /*  Character Mythic Keystone Profile API */
            case 'character-mythic-keystone-profile-index':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/mythic-keystone-profile';
            case 'character-mythic-keystone-season-details':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/mythic-keystone-profile/season/'.$fields['seasonId'];

            /*  Character Professions API */
            case 'character_professions':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/professions';

            /*  Character Profile API */
            case 'character_profile_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8');
            case 'character_profile_status':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/status';

            /*  Character PvP API */
            case 'character_pvp_bracket_statistics':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/pvp-bracket/'.$fields['pvpBracket'];
            case 'character_pvp_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/pvp-summary';

            /*  Character Quests API */
            case 'character_quests':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/quests';
            case 'character_completed_quests':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/quests/completed';

            /*  Character Reputations API */
            case 'character_reputations_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/reputations';

            /*  Character Soulbinds API */
            case 'character_soulbinds':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/soulbinds';

            /*  Character Specializations API */
            case 'character_specializations_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/specializations';

            /*  Character Statistics API */
            case 'character_statistics_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/statistics';

            /*  Character Titles API */
            case 'character_titles_summary':
                return '/profile/wow/character/'.$fields['server'].'/'.mb_strtolower($fields['name'], 'UTF-8').'/titles';

            /*  Guild API */
            case 'guild':
                return '/data/wow/guild/'.$fields['server'].'/'.$fields['nameSlug'];
            case 'guild_activity':
                return '/data/wow/guild/'.$fields['server'].'/'.$fields['nameSlug'].'/activity';
            case 'guild_achievements':
                return '/data/wow/guild/'.$fields['server'].'/'.$fields['nameSlug'].'/achievements';
            case 'guild_roster':
                return '/data/wow/guild/'.$fields['server'].'/'.$fields['nameSlug'].'/roster';
        }
        throw new InvalidArgumentException ('Unknown Blizzard web API request ' . $class);
    }

    public function _request_namespace($class)
    {
        switch (str_replace('-', '_', $class))
        {
            case 'account':
                return null;

            case 'achievement':
            case 'achievement_categories_index':
            case 'achievement_category':
            case 'achievement_media':
            case 'achievements_index':
            case 'azerite_essence':
            case 'azerite_essence_media':
            case 'azerite_essence_search':
            case 'azerite_essences_index':
            case 'conduit':
            case 'conduit_index':
            case 'covenant':
            case 'covenant_index':
            case 'covenant_media':
            case 'creature':
            case 'creature_display_media':
            case 'creature_families_index':
            case 'creature_family':
            case 'creature_family_media':
            case 'creature_search':
            case 'creature_type':
            case 'creature_types_index':
            case 'guild_crest_border_media':
            case 'guild_crest_components_index':
            case 'guild_crest_emblem_media':
            case 'item':
            case 'item_class':
            case 'item_classes_index':
            case 'item_media':
            case 'item_search':
            case 'item_set':
            case 'item_sets_index':
            case 'item_subclass':
            case 'journal_encounter':
            case 'journal_encounter_search':
            case 'journal_encounters_index':
            case 'journal_expansion':
            case 'journal_expansions_index':
            case 'journal_instance':
            case 'journal_instance_media':
            case 'journal_instances_index':
            case 'media_search':
            case 'modified-crafting-reagent-slot-type':
            case 'modified-crafting-reagent-slot-type-index':
            case 'modified_crafting_category':
            case 'modified_crafting_category_index':
            case 'modified_crafting_index':
            case 'mount':
            case 'mount_search':
            case 'mounts_index':
            case 'mythic_keystone_affix':
            case 'mythic_keystone_affix_media':
            case 'mythic_keystone_affixes_index':
            case 'pet':
            case 'pet_abilities_index':
            case 'pet_ability':
            case 'pet_ability_media':
            case 'pet_media':
            case 'pets_index':
            case 'playable_class':
            case 'playable_class_media':
            case 'playable_classes_index':
            case 'playable_race':
            case 'playable_races_index':
            case 'playable_specialization':
            case 'playable_specialization_media':
            case 'playable_specializations_index':
            case 'power_type':
            case 'power_types_index':
            case 'profession':
            case 'profession_media':
            case 'profession_skill_tier':
            case 'professions_index':
            case 'pvp_talent':
            case 'pvp_talent_slots':
            case 'pvp_talents_index':
            case 'pvp_tier':
            case 'pvp_tier_media':
            case 'pvp_tiers_index':
            case 'quest':
            case 'quest_area':
            case 'quest_areas_index':
            case 'quest_categories_index':
            case 'quest_category':
            case 'quest_type':
            case 'quest_types_index':
            case 'quests_index':
            case 'realm':
            case 'realm_search':
            case 'realms_index':
            case 'recipe':
            case 'recipe_media':
            case 'region':
            case 'regions_index':
            case 'reputation_faction':
            case 'reputation_factions_index':
            case 'reputation_tiers':
            case 'reputation_tiers_index':
            case 'soulbind':
            case 'soulbind_index':
            case 'spell':
            case 'spell_media':
            case 'spell_search':
            case 'talent':
            case 'talent_tree':
            case 'talent_tree_index':
            case 'talent_tree_nodes':
            case 'talents_index':
            case 'tech_talent':
            case 'tech_talent_index':
            case 'tech_talent_media':
            case 'tech_talent_tree':
            case 'tech_talent_tree_index':
            case 'title':
            case 'titles_index':
                return 'static';

            case 'auctions':
            case 'commodities':
            case 'connected_realm':
            case 'connected_realms_index':
            case 'connected_realms_search':
            case 'mythic_keystone_dungeon':
            case 'mythic_keystone_dungeons_index':
            case 'mythic_keystone_index':
            case 'mythic_keystone_leaderboard':
            case 'mythic_keystone_leaderboards_index':
            case 'mythic_keystone_period':
            case 'mythic_keystone_periods_index':
            case 'mythic_keystone_season':
            case 'mythic_keystone_seasons_index':
            case 'mythic_raid_leaderboard':
            case 'pvp_leaderboard':
            case 'pvp_leaderboards_index':
            case 'pvp_rewards_index':
            case 'pvp_season':
            case 'pvp_seasons_index':
                return 'dynamic';

            case 'account_collections_index':
            case 'account_mounts_collection_summary':
            case 'account_pets_collection_summary':
            case 'account_profile_summary':
            case 'character-mythic-keystone-profile-index':
            case 'character-mythic-keystone-season-details':
            case 'character_achievement_statistics':
            case 'character_achievements_summary':
            case 'character_appearance_summary':
            case 'character_collections':
            case 'character_collections_mounts':
            case 'character_collections_pets':
            case 'character_completed_quests':
            case 'character_dungeons':
            case 'character_encounters_summary':
            case 'character_equipment_summary':
            case 'character_hunter_pets_summary':
            case 'character_media_summary':
            case 'character_professions':
            case 'character_profile_status':
            case 'character_profile_summary':
            case 'character_pvp_bracket_statistics':
            case 'character_pvp_summary':
            case 'character_quests':
            case 'character_raids':
            case 'character_reputations_summary':
            case 'character_soulbinds':
            case 'character_specializations_summary':
            case 'character_statistics_summary':
            case 'character_titles_summary':
            case 'guild':
            case 'guild_achievements':
            case 'guild_activity':
            case 'guild_roster':
            case 'protected_character_profile_summary':
            case 'wowprofile':
                return 'profile';
        }
        throw new InvalidArgumentException ('Unknown Blizzard web API request ' . $class);
    }


    /**
     * Fetch a protected ressource
     *
     * @param string $protected_ressource_url Protected resource URL
     * @param array  $parameters Array of parameters
     * @param string $http_method HTTP Method to use (POST, PUT, GET, HEAD, DELETE)
     * @param array  $http_headers HTTP headers
     * @param int    $form_content_type HTTP form content type to use
     * @return array
     */
    public function fetch($protected_resource_url, $parameters = array(), $http_headers = array(), $http_method = self::HTTP_METHOD_GET, $form_content_type = self::HTTP_FORM_CONTENT_TYPE_MULTIPART)
    {
        $protected_resource_url = self::_buildUrl($protected_resource_url, $parameters);

        if ($this->access_token) {
            switch ($this->access_token_type) {
                case self::ACCESS_TOKEN_URI:
                    if (is_array($parameters)) {
                        $parameters[$this->access_token_param_name] = $this->access_token;
                    } else {
                        throw new InvalidArgumentException(
                            'You need to give parameters as array if you want to give the token within the URI.',
                            InvalidArgumentException::REQUIRE_PARAMS_AS_ARRAY
                        );
                    }
                    break;
                case self::ACCESS_TOKEN_BEARER:
                    $http_headers['Authorization'] = 'Bearer ' . $this->access_token;
                    break;
                case self::ACCESS_TOKEN_OAUTH:
                    $http_headers['Authorization'] = 'OAuth ' . $this->access_token;
                    break;
                case self::ACCESS_TOKEN_MAC:
                    $http_headers['Authorization'] = 'MAC ' . $this->generateMACSignature($protected_resource_url, $parameters, $http_method);
                    break;
                default:
                    throw new Exception('Unknown access token type.', Exception::INVALID_ACCESS_TOKEN_TYPE);
            }
        }

        $result = $this->executeRequest($protected_resource_url, $parameters, $http_method, $http_headers, $form_content_type);

        return $result;
    }

    /**
     * Generate the MAC signature
     *
     * @param string $url Called URL
     * @param array  $parameters Parameters
     * @param string $http_method Http Method
     * @return string
     */
    private function generateMACSignature($url, $parameters, $http_method)
    {
        $timestamp = time();
        $nonce = uniqid();
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['port']))
        {
            $parsed_url['port'] = ($parsed_url['scheme'] == 'https') ? 443 : 80;
        }
        if ($http_method == self::HTTP_METHOD_GET) {
            if (is_array($parameters)) {
                $parsed_url['path'] .= '?' . http_build_query($parameters, null, '&');
            } elseif ($parameters) {
                $parsed_url['path'] .= '?' . $parameters;
            }
        }

        $signature = base64_encode(hash_hmac($this->access_token_algorithm,
                    $timestamp . "\n"
                    . $nonce . "\n"
                    . $http_method . "\n"
                    . $parsed_url['path'] . "\n"
                    . $parsed_url['host'] . "\n"
                    . $parsed_url['port'] . "\n\n"
                    , $this->access_token_secret, true));

        return 'id="' . $this->access_token . '", ts="' . $timestamp . '", nonce="' . $nonce . '", mac="' . $signature . '"';
    }

    /**
     * Execute a request (with curl)
     *
     * @param string $url URL
     * @param mixed  $parameters Array of parameters
     * @param string $http_method HTTP Method
     * @param array  $http_headers HTTP Headers
     * @param int    $form_content_type HTTP form content type to use
     * @return array
     */
    private function executeRequest($url, $parameters = array(), $http_method = self::HTTP_METHOD_GET, array $http_headers = null, $form_content_type = self::HTTP_FORM_CONTENT_TYPE_MULTIPART)
    {
        //echo $url.'<br>'.$http_method.'<br>';

        $curl_options = array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
        );
        switch($http_method) {
            case self::HTTP_METHOD_POST:
                $curl_options[CURLOPT_POST] = true;

                /* No break */
            case self::HTTP_METHOD_PUT:
            case self::HTTP_METHOD_PATCH:

                /**
                 * Passing an array to CURLOPT_POSTFIELDS will encode the data as multipart/form-data,
                 * while passing a URL-encoded string will encode the data as application/x-www-form-urlencoded.
                 * http://php.net/manual/en/function.curl-setopt.php
                 */
                if(is_array($parameters) && self::HTTP_FORM_CONTENT_TYPE_APPLICATION === $form_content_type) {
                    $parameters = http_build_query($parameters, null, '&');
                }
                $curl_options[CURLOPT_POSTFIELDS] = $parameters;
                break;
            case self::HTTP_METHOD_HEAD:
                $curl_options[CURLOPT_NOBODY] = true;
                /* No break */
            case self::HTTP_METHOD_DELETE:
            case self::HTTP_METHOD_GET:

                break;
            default:
                break;
        }
        //echo $url.'<br>';
        $curl_options[CURLOPT_URL] = $url;
        $curl_options[CURLOPT_HEADER] = true;

        if (is_array($http_headers)) {
            $header = array();
            foreach($http_headers as $key => $parsed_urlvalue) {
                $header[] = "$key: $parsed_urlvalue";
            }
            $curl_options[CURLOPT_HTTPHEADER] = $header;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $curl_options);
        // https handling
        if (!empty($this->certificate_file))
        {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_CAINFO, $this->certificate_file);
        } else {
            // bypass ssl verification
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }
        if (!empty($this->curl_options))
        {
            curl_setopt_array($ch, $this->curl_options);
        }

        curl_setopt($ch, CURLOPT_ACCEPT_ENCODING, '');

        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $this->errno    = curl_errno($ch);
        $this->error    = curl_error($ch);

        $header_size = curl_getinfo($ch,CURLINFO_HEADER_SIZE);

        $this->usage['responce_code'] = $http_code;
        $this->usage['content_type'] = $content_type;

        $header = $this->get_headers_from_curl_response(substr($result, 0, $header_size));
        $result = substr($result, $header_size);
        $effective_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);

        curl_close($ch);

        $json_decode = json_decode($result, true);
        if (null === $json_decode) {
            return $result;
        }

        $json_decode['header'] = $header;
        $json_decode['http_code'] = $http_code;
        $json_decode['last_url'] = $effective_url;

        if ($this->errno)
        {
            $json_decode['http_code'] = '~' . $json_decode['http_code'];
        }

        return $json_decode;
    }

    public function get_headers_from_curl_response($response)
    {
        $headers = array();

        $header_text = substr($response, 0, strpos($response, "\r\n\r\n"));

        foreach (explode("\r\n", $header_text) as $i => $line)
            if ($i === 0)
                $headers['http_code'] = $line;
            else
            {
                list ($key, $value) = explode(': ', $line);

                $headers[$key] = $value;
            }

        return $headers;
    }
    /**
     * Set the name of the parameter that carry the access token
     *
     * @param string $name Token parameter name
     * @return void
     */
    public function setAccessTokenParamName($name)
    {
        $this->access_token_param_name = $name;
    }

    /**
     * Converts the class name to camel case
     *
     * @param  mixed  $grant_type  the grant type
     * @return string
     */
    private function convertToCamelCase($grant_type)
    {
        $parts = explode('_', $grant_type);
        array_walk($parts, function(&$item) { $item = ucfirst($item);});
        return implode('', $parts);
    }
}

class Exception extends \Exception
{
    const CURL_NOT_FOUND                     = 0x01;
    const CURL_ERROR                         = 0x02;
    const GRANT_TYPE_ERROR                   = 0x03;
    const INVALID_CLIENT_AUTHENTICATION_TYPE = 0x04;
    const INVALID_ACCESS_TOKEN_TYPE          = 0x05;
}

class InvalidArgumentException extends \InvalidArgumentException
{
    const INVALID_GRANT_TYPE      = 0x01;
    const CERTIFICATE_NOT_FOUND   = 0x02;
    const REQUIRE_PARAMS_AS_ARRAY = 0x03;
    const MISSING_PARAMETER       = 0x04;
}
