<?php namespace Zizaco\Confide;

use Illuminate\Auth\UserInterface;
use LaravelBook\Ardent\Ardent;
use J20\Uuid\Uuid;

class ConfideUser extends Ardent implements UserInterface {

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'users';

    /**
     * Laravel application
     *
     * @var Illuminate\Foundation\Application
     */
    public static $app;

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = array('password');

    /**
     * List of attribute names which should be hashed. (Ardent)
     *
     * @var array
     */
    public static $passwordAttributes = array('password');

    /**
     * This way the model will automatically replace the plain-text password
     * attribute (from $passwordAttributes) with the hash checksum on save
     *
     * @var bool
     */
    public $autoHashPasswordAttributes = true;

    /**
     * Ardent validation rules
     *
     * @var array
     */
    public static $rules = array(
        'username' => 'required|alpha_dash|unique:users',
        'email' => 'required|email|unique:users',
        'password' => 'required|between:4,11|confirmed',
        'password_confirmation' => 'between:4,11',
    );

    /**
     * Create a new ConfideUser instance.
     */
    public function __construct( array $attributes = array() )
    {
        parent::__construct( $attributes );

        if ( ! static::$app )
            static::$app = app();

        $this->table = static::$app['config']->get('auth.table');
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Get the password for the user.
     *
     * @return string
     */
    public function getAuthPassword()
    {
        return $this->password;
    }

    /**
     * Confirm the user (usually means that the user)
     * email is valid.
     *
     * @return bool
     */
    public function confirm()
    {
        $this->confirmed = 1;

        // ConfideRepository will update the database
        static::$app['confide.repository']
            ->confirmUser( $this );

        return true;
    }

    /**
     * Send email with information about password reset
     *
     * @return string
     */
    public function forgotPassword()
    {
        // ConfideRepository will generate token (and save it into database)
        $token = static::$app['confide.repository']
            ->forgotPassword( $this );

        $view = static::$app['config']->get('confide::email_reset_password');

        $this->sendEmail( 'confide::confide.email.password_reset.subject', $view, array('name' => $this->name, 'token' => $token) );

        return true;
    }

    /**
     * Change user password
     *
     * @param  $params
     * @return string
     */
    public function resetPassword( $params )
    {
        $password = array_get($params, 'password', '');
        $passwordConfirmation = array_get($params, 'password_confirmation', '');

        if ( $password == $passwordConfirmation )
        {
            return static::$app['confide.repository']
                ->changePassword( $this, static::$app['hash']->make($password) );
        }
        else{
            return false;
        }
    }

    /**
     * Overwrite the Ardent save method. Saves model into
     * database
     *
     * @param array $rules:array
     * @param array $customMessages
     * @param array $options
     * @param \Closure $beforeSave
     * @param \Closure $afterSave
     * @return bool
     */
    public function save( array $rules = array(), array $customMessages = array(), array $options = array(), \Closure $beforeSave = null, \Closure $afterSave = null, $force = false )
    {
      return $this->real_save( $rules, $customMessages, $options, $beforeSave, $afterSave );
    }
    
    /**
     * Ardent method overloading:
     * Before save the user. Generate a confirmation
     * code if is a new user.
     *
     * @return bool
     */
    public function beforeSave()
    {
        if ( empty($this->id) )
        {
            $this->confirmation_code = str_random(8);
        }

        /*
         * Remove password_confirmation field before save to
         * database.
         */
        if ( isset($this->password_confirmation) )
        {
            unset( $this->password_confirmation );
        }

        return true;
    }

    /**
     * Ardent method overloading:
     * After save, delivers the confirmation link email.
     * code if is a new user.
     *
     * @return bool
     */
    public function afterSave()
    {
        if (! $this->confirmed && ! static::$app['cache']->get('confirmation_email_'.$this->id) )
        {
            $view = static::$app['config']->get('confide::email_account_confirmation');

            $this->sendEmail( 'confide::confide.email.account_confirmation.subject', $view, array('user' => $this) );

            // Save in cache that the email has been sent.
            $signup_cache = (int)static::$app['config']->get('confide::signup_cache');
            if ($signup_cache !== 0)
            {
                static::$app['cache']->put('confirmation_email_'.$this->id, true, $signup_cache);
            }
        }

        return true;
    }

    /**
     * Runs the real eloquent save method or returns
     * true if it's under testing. Because Eloquent
     * and Ardent save methods are not Confide's
     * responsibility.
     *
     * @param array $rules
     * @param array $customMessages
     * @param array $options
     * @param \Closure $beforeSave
     * @param \Closure $afterSave
     * @return bool
     */
    protected function real_save( array $rules = array(), array $customMessages = array(), array $options = array(), \Closure $beforeSave = null, \Closure $afterSave = null )
    {
        if ( defined('CONFIDE_TEST') )
        {
            $this->beforeSave();
            $this->afterSave();
            return true;
        }
        else {
            // If this is an update, and if the user type in a password in either
            // password or password_confirmation, remove the rules related to that.  
            if ($this->exists)
            {
              if (empty($rules)) $rules = static::$rules;
              
            if  (!$this->password && !$this->password_confirmation )
              {  
                $this->password = $this->getOriginal('password');
                $this->autoHashPasswordAttributes = false;
                unset($rules['password'], $rules['password_confirmation']);
              }
              // Use the built in Ardent function override unique trigger for this user
              $rules = $this->buildUniqueExclusionRules($rules);
              
              
            }
            return parent::save( $rules, $customMessages, $options, $beforeSave, $afterSave );
        }
    }
    
    /**
     * On most websites, when a user updates his details and leaves the password empty
     * the password should be left alone. Confide will handle that for you automatically
     * and you don't need to call this function.
     * If however, you are using Former's live inbrowser form validation, this helper function 
     * would filter out the required section while keeping things like max, min, etc
     * @param array $rules
     */
    public function filterPasswordRequirement(array $rules = array())
    {
      
    }

    /**
     * Add the namespace 'confide::' to view hints.
     * this makes possible to send emails using package views from
     * the command line.
     *
     * @return void
     */
    protected static function fixViewHint()
    {
        if (isset(static::$app['view.finder']))
            static::$app['view.finder']->addNamespace('confide', __DIR__.'/../../views');
    }

    /**
     * Send email using the lang sentence as subject and the viewname
     *
     * @param mixed $subject_translation
     * @param mixed $view_name
     * @param array $params
     * @return voi.
     */
    protected function sendEmail( $subject_translation, $view_name, $params = array() )
    {
        if ( static::$app['config']->getEnvironment() == 'testing' )
            return;

        static::fixViewHint();

        $user = $this;
        
        static::$app['mailer']->send($view_name, $params, function($m) use ($subject_translation, $user)
        {
            $m->to( $user->email )
                ->subject( ConfideUser::$app['translator']->get($subject_translation) );
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Deprecated methods
    |--------------------------------------------------------------------------
    |
    */

    /**
     * [Deprecated] Generates UUID and checks it for uniqueness against a table/column.
     *
     * @deprecated
     * @param  $table
     * @param  $field
     * @return string
     */
    protected function generateUuid($table, $field)
    {
        return md5( uniqid(mt_rand(), true) );
    }

}
