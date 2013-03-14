// Interaction for the configuration admin panel

(function($){

  // Hide/unhide depending sections
  function toggleLoginOpts() {
    var isChecked = parseInt(
                      $("input[name=acctmgr_login]:checked").val());
    var section = $("#acctmgr_login_opts");
    if (isChecked === 0) {
      $("input[name=auth_cookie_lifetime]").change();
      section.slideUp();
    }
    else {
      $("input[name=auth_cookie_lifetime]").change();
      section.slideDown();
    }
  }

  function togglePreview() {
    var fileChecked = $("input[name=init_store_file]:checked").val();
    var isChecked = $("input[name=init_store]:checked").val();
    $("fieldset.ini").hide();
    if (isChecked === "file") {
      $("fieldset#" + fileChecked).show();
    } else {
      $("fieldset#" + isChecked).show();
    }
  }

  function toggleFileStore() {
    var isChecked = $("input[name=init_store]:checked").val();
    var section = $("#init_store_file");
    if (isChecked === "file") {
      section.slideDown();
    }
    else {
      section.slideUp();
    }
  }

  function toggleEtcStore() {
    var isChecked = $("input[name=init_store]:checked").val();
    var section = $("#etc_store_cfg");
    if (isChecked === "etc") {
      section.slideDown();
    }
    else {
      section.slideUp();
    }
  }

  function toggleRestart() {
    var button = $("#restart");
    if (!$("input[name=refresh_passwd]").is(':checked')) {
      button.attr('disabled','disabled');
    }
    else {
      button.removeAttr('disabled');
    }
  }

  function toggleRegisterOpts() {
    var section = $("#acctmgr_register_opts");
    if (!$("input[name=acctmgr_register]").is(':checked')) {
      section.slideUp();
    }
    else {
      section.slideDown();
    }
  }

  function toggleGuardOpts() {
    var section = $("#acctmgr_guard_opts");
    if (!$("input[name=acctmgr_guard]").is(':checked')) {
      section.slideUp();
    }
    else {
      section.slideDown();
    }
  }

  $(document).ready(function($) {
    // Hide/unhide depending elements
    $("input[name=auth_cookie_lifetime]").change(function() {
      var isChecked = parseInt(
                        $("input[name=acctmgr_login]:checked").val());
      var oldValue = parseInt($("#auth_cookie_lifetime_old").val());
      if (parseInt($("input[name=auth_cookie_lifetime]")
                     .val()) != oldValue ||
                     (isChecked === 0 && oldValue === 0)) {
        $("span#pretty_auth_cookie_lifetime").hide();
      }
      else {
        $("span#pretty_auth_cookie_lifetime").show();
      }
    });

    $("input[name=user_lock_max_time]").change(function() {
      var oldValue = parseInt($("#user_lock_max_time_old").val());
      if (parseInt($("input[name=user_lock_max_time]")
                     .val()) != oldValue) {
        $("span#pretty_user_lock_max_time").hide();
      }
      else {
        $("span#pretty_user_lock_max_time").show();
      }
    });

    // Hide/unhide depending sections
    $("input[type=radio][name=init_store]").click(function() {
      togglePreview();
    });
    $("input[type=radio][name=init_store_file]").click(function() {
      togglePreview();
    });
    $("input[name=init_store]:checked").click();


    $("input[name=login_attempt_max_count]").change(function() {
      var currVal = parseInt(
          $("input[name=login_attempt_max_count]").val());
      var section = $("div#user_lock_time");
      if (currVal === 0) {
        section.slideUp();
      }
      else if (currVal < 0) {
        $("input[name=login_attempt_max_count]").val('0');
        section.slideUp();
      }
      else{
        section.slideDown();
      }
    }).change();

    $("input[name=user_lock_time]").change(function() {
      var currVal = parseInt($("input[name=user_lock_time]").val());
      var section = $("div#user_lock_time_progression");
      if (currVal === 0) {
        section.slideUp();
      }
      else if (currVal < 0) {
        $("input[name=user_lock_time]").val('0');
        section.slideUp();
      }
      else{
        section.slideDown();
      }
    }).change();

    $("input[name=user_lock_time_progression]").change(function() {
      var currVal = parseFloat(
                      $("input[name=user_lock_time_progression]").val());
      var section = $("div#user_lock_max_time");
      if (currVal === 1) {
        section.slideUp();
      }
      else if (currVal < 1) {
        $("input[name=user_lock_time_progression]").val('1');
        section.slideUp();
      }
      else {
        section.slideDown();
      }
    }).change();

    // Bind functions to input elements and fix initial section
    // visibility depending on some input state
    $("input[type=radio][name=acctmgr_login]").click(function() {
      toggleLoginOpts();
    });
    toggleLoginOpts();

    $("input[type=radio][name=init_store]").click(function() {
      toggleFileStore();
    });
    toggleFileStore();
    $("input[type=radio][name=init_store]").click(function() {
      toggleEtcStore();
    });
    toggleEtcStore();
    $("input[type=checkbox][name=acctmgr_register]").click(function() {
      toggleRegisterOpts();
    });
    toggleRestart()
    $("input[type=checkbox][name=refresh_passwd]").click(function() {
      toggleRestart();
    });
    toggleRegisterOpts();
    $("input[type=checkbox][name=acctmgr_guard]").click(function() {
      toggleGuardOpts();
    });
    toggleGuardOpts();
  });

})(jQuery);
