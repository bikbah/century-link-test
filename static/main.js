(function() {
  $(document).ready(function() {

    $('#tokenText').hide();
    $('#secretHandlerResponse').hide();

    $('#btnSignIn').click(function(e) {
      e.preventDefault();
      loginData = {
        login: $('#inpLogin').val(),
        password: $('#inpPassword').val()
      }
      $.ajax({
        method: "POST",
        url: "http://localhost:8080/login",
        dataType: "json",
        data: JSON.stringify(loginData),
        contentType: "application/json",
        success: function(data) {
          $('#tokenText').show();
          console.log(data);
          $('#tokenText p').text(data["access_token"]);
        }
      });
    });

    $('#btnSecretHandler').click(function(e) {
      e.preventDefault();
      token = $('#inpToken').val();

      $.ajax({
        method: "GET",
        url: "http://localhost:8080/secret",
        headers: {
          "Authorization": "Bearer " + token
        },
        success: function(data) {
          $('#secretHandlerResponse').show();
          console.log(data);
          $('#secretHandlerResponse p').text(data);
        }
      });
    });

  });
})();
